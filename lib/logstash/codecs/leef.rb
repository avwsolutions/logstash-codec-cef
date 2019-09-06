# encoding: utf-8
require "logstash/codecs/base"
require "logstash/util/charset"
require "json"
require "socket"
require "time"

# Implementation of a Logstash codec for the qRADAR Log Event Extended Format (LEEF)
# Based on Version 1.0 of Implementing QRadar LEEF.
# https://www.ibm.com/developerworks/community/wikis/form/anonymous/api/wiki/9989d3d7-02c1-444e-92be-576b33d2f2be/page/3dc63f46-4a33-4e0b-98bf-4e55b74e556b/attachment/a19b9122-5940-4c89-ba3e-4b4fc25e2328/media/QRadar_LEEF_Format_Guide.pdf
 
class LogStash::Codecs::LEEF < LogStash::Codecs::Base
  config_name "leef"

  LEEF_V1_DELIMITER = "\t"

  config :leefversion, :validate => :string, :default => "2.0"

  config :leefdelimiter, :validate => :string, :default => LEEF_V1_DELIMITER

  # Field to enable the default syslog header, which uses the default `%{host}` field for hostname and the timestamp is generated by the codec parsing time. If no value is set the hostname is set to the `hostname` value where logstash is running.
  config :syslogheader, :validate => :boolean, :default => true

  config :sysloghost, :validate => :string, :default => "logstash"
  
  # Device vendor field in LEEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :vendor, :validate => :string, :default => "Elastic"

  # Device product field in LEEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :product, :validate => :string, :default => "Logstash"

  # Device version field in LEEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :version, :validate => :string, :default => "4.0.0"

  # EventID field in LEEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :eventid, :validate => :string, :default => "Logstash"

  # Name field in LEEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  #config :name, :validate => :string, :default => "Logstash"

  # Deprecated severity field for LEEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  #
  # This field is used only if :severity is unchanged set to the default value.
  #
  # Defined as field of type string to allow sprintf. The value will be validated
  # to be an integer in the range from 0 to 10 (including).
  # All invalid values will be mapped to the default of 6.
  #config :sev, :validate => :string, :default => "6", :deprecated => "This setting is being deprecated, use :severity instead."

  # Severity field in LEEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  #
  # Defined as field of type string to allow sprintf. The value will be validated
  # to be an integer in the range from 0 to 10 (including).
  # All invalid values will be mapped to the default of 6.
  #config :severity, :validate => :string, :default => "6"

  # Fields to be included in LEEF extension part as key/value pairs
  config :fields, :validate => :array, :default => []

  # If raw_data_field is set, during decode of an event an additional field with
  # the provided name is added, which contains the raw data.
  config :raw_data_field, :validate => :string


  # Common Header fields for LEEF. In leefVersion=LEEF:2.0 there is a new optional field leefDelimiter
  HEADER_FIELDS = ['leefVersion', 'productVendor', 'deviceProduct','deviceVersion','deviceEventId'] 

  # SYSLOG_HEADER_PATTERN = /^(?:<\d+>)?\s*([A-Z][a-z]{2}\s+\d+\s\d+:\d+:\d+)\s(.*?)\s/
  SYSLOG_HEADER_PATTERN = /^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s(.*?)\s+/

  # A LEFT Header is a sequence of zero or more:
  #  - backslash-escaped pipes; OR
  #  - backslash-escaped backslashes; OR
  #  - non-pipe characters
  HEADER_PATTERN = /(?:\\\||\\\\|[^|])*?/
  HEADER_ESCAPE_CAPTURE = /\\([\\|])/

  # Cache of a scanner pattern that _captures_ a HEADER followed by an unescaped pipe
  HEADER_SCANNER = /(#{HEADER_PATTERN})#{Regexp.quote('|')}/

  LEEF_DELIM_PATTERN = /^(.|0?[xX][0-9A-Fa-f]{2,4})#{Regexp.quote('|')}/


  # Cache of a gsub pattern that matches a backslash-escaped backslash or backslash-escaped equals, _capturing_ the escaped character
  EXTENSION_VALUE_ESCAPE_CAPTURE = /\\([\\=])/
  
  # While the original CEF spec calls out that extension keys must be alphanumeric and must not contain spaces,
  # in practice many "CEF" producers like the Arcsight smart connector produce non-legal keys including underscores,
  # commas, periods, and square-bracketed index offsets.
  #
  # To support this, we look for a specific sequence of characters that are followed by an equals sign. This pattern
  # will correctly identify all strictly-legal keys, and will also match those that include a dot "subkey"
  #
  # That sequence must begin with one or more `\w` (word: alphanumeric + underscore), which _optionally_ may be followed
  # by "subkey" sequence consisting of a literal dot (`.`) followed by a non-whitespace character, then one or more word
  # characters, and then one or more characters that do not convey semantic meaning within CEF (e.g., literal-pipe (`|`),
  # whitespace (`\s`), literal-dot (`.`), literal-equals (`=`), or literal-backslash ('\')).
  EXTENSION_KEY_PATTERN = /(?:\w+(?:\.[^\s]\w+[^\|\s\.\=\\]+)?(?==))/
 
  # Some CEF extension keys seen in the wild use an undocumented array-like syntax that may not be compatible with
  # the Event API's strict-mode FieldReference parser (e.g., `fieldname[0]`).
  # Cache of a `String#sub` pattern matching array-like syntax and capturing both the base field name and the
  # array-indexing portion so we can convert to a valid FieldReference (e.g., `[fieldname][0]`).
  EXTENSION_KEY_ARRAY_CAPTURE = /^([^\[\]]+)((?:\[[0-9]+\])+)$/ # '[\1]\2'


  public
  def register
    # LEEF input MUST be UTF-8, per the LEEF documentation:
    # https://www.ibm.com/support/knowledgecenter/SS42VS_DSM/com.ibm.dsm.doc/c_LEEF_Format_Guide_intro.html
    @utf8_charset = LogStash::Util::Charset.new('UTF-8')
    @utf8_charset.logger = self.logger

    if @delimiter
      # Logstash configuration doesn't have built-in support for escaping,
      # so we implement it here. Feature discussion for escaping is here:
      #   https://github.com/elastic/logstash/issues/1645
      @delimiter = @delimiter.gsub("\\r", "\r").gsub("\\n", "\n")
      @buffer = FileWatch::BufferedTokenizer.new(@delimiter)
    end
  end

private
def store_header_field(event,field_name,field_data)
    #Unescape pipes and backslash in header fields
    event.set(field_name,field_data.gsub(/\\\|/, '|').gsub(/\\\\/, '\\')) unless field_data.nil?
end

  public
  def decode(data, &block)
    if @delimiter
      @buffer.extract(data).each do |line|
        handle(line, &block)
      end
    else
      handle(data, &block)
    end
  end

  public
  def handle(data, &block)
    event = LogStash::Event.new
    event.set(raw_data_field, data) unless raw_data_field.nil?

    @utf8_charset.convert(data)

    # Several of the many operations in the rest of this method will fail when they encounter UTF8-tagged strings
    # that contain invalid byte sequences; fail early to avoid wasted work.
    fail('invalid byte sequence in UTF-8') unless data.valid_encoding?

    # Strip any quotations at the start and end, flex connectors seem to send this
    if data[0] == "\""
      data = data[1..-2]
    end


    # Search for syslog header
    SYSLOG_HEADER_PATTERN.match(data) do |syslog|
      event.set('syslogTime', syslog[1])
      event.set('syslogHost', syslog[2])
      data = syslog.post_match
      @syslogheader = true
    end

    # Use a scanning parser to capture the HEADER_FIELDS"""!!!|@@@@@@
    unprocessed_data = data
    HEADER_FIELDS.each do |field_name|
      match_data = HEADER_SCANNER.match(unprocessed_data)
      break if match_data.nil? # missing fields

      escaped_field_value = match_data[1]
      next if escaped_field_value.nil?

      # process legal header escape sequences
      unescaped_field_value = escaped_field_value.gsub(HEADER_ESCAPE_CAPTURE, '\1')

      event.set(field_name, unescaped_field_value)
      unprocessed_data = match_data.post_match
    end

    event.set('leefVersion', event.get('leefVersion').sub(/^LEEF:/, ''))

    # in LEEF version 2.0, field delimiter can be chosen
    if event.get('leefVersion') == '2.0' then
      LEEF_DELIM_PATTERN.match(unprocessed_data) do |match_data|
        leefdelimiter = match_data[1]
        event.set('leefDelimiter', leefdelimiter)
        unprocessed_data = match_data.post_match
      end
    end

   # Create the key/value scanner
    leefdelimiter = get_leefdelimiter_value(get_leefdelimiter(event))
    red = Regexp.quote(leefdelimiter)
    value_pattern = /(?:\\#{red}|\\\\|[^#{red}])*/
    scanner  = /(#{EXTENSION_KEY_PATTERN})=(#{value_pattern})(?:#{red}|$)/
    
    message = unprocessed_data
    message.scan(scanner) do |extension_field_key, raw_extension_field_value|
      # convert extension field name to strict legal field_reference, fixing field names with ambiguous array-like syntax
      extension_field_key = extension_field_key.sub(EXTENSION_KEY_ARRAY_CAPTURE, '[\1]\2') if extension_field_key.end_with?(']')

      # process legal extension field value escapes
      extension_field_value = raw_extension_field_value.gsub(EXTENSION_VALUE_ESCAPE_CAPTURE, '\1')

      event.set(extension_field_key, extension_field_value)
    end

    yield event

  rescue => e
    @logger.error("Failed to decode LEEF payload. Generating failure event with payload in message field.", :error => e.message, :backtrace => e.backtrace, :data => data)
    yield LogStash::Event.new("message" => data, "tags" => ["_leefparsefailure"])
  end

  public
  def encode(event)
    # "LEEF:1.0|Elastic|Logstash|2.3.3|EventID|"

    sheader = ""

    if @syslogheader
        time = Time.new
        syslogtime = sanitize_header_field(event.get('syslogTime')) 
        syslogtime = time.strftime("%b %d %H:%M:%S") if syslogtime == ""
        syslogtime = "<13>" + syslogtime

        sysloghost = sanitize_header_field(event.sprintf(@sysloghost))
        if sysloghost == ""
                sysloghost = Socket.gethostname
        end

        sheader = "#{syslogtime} #{sysloghost} "
    end

    leefversion = get_leefversion(event)
    
    vendor = sanitize_header_field(event.sprintf(@vendor))
    vendor = self.class.get_config["vendor"][:default] if vendor == "" 

    product = sanitize_header_field(event.sprintf(@product))
    product = self.class.get_config["product"][:default] if product == ""

    version = sanitize_header_field(event.sprintf(@version))
    version = self.class.get_config["version"][:default] if version == ""

    eventid = sanitize_header_field(event.sprintf(@eventid))
    eventid = self.class.get_config["eventid"][:default] if eventid == ""

    headers = ["LEEF:#{leefversion}", vendor, product, version, eventid]

    leefdelimiter = get_leefdelimiter(event)
    if leefversion == "2.0"
      headers << leefdelimiter
    end

    delim  = get_leefdelimiter_value(leefdelimiter)

    header = headers.join("|")
    values = @fields.map {|fieldname| get_value(fieldname, event)}.compact.join(delim)

    @on_event.call(event, "#{sheader}#{header}|#{values}#{@delimiter}")

  end

  private
  def get_leefversion(event)
    leefversion = sanitize_header_field(event.sprintf(@leefversion))
    leefversion = self.class.get_config["leefversion"][:default] if leefversion == ""

    return leefversion
  end

  private
  def get_leefdelimiter(event)
    if get_leefversion(event) == "2.0"
      leefdelimiter = event.get('leefDelimiter')
      leefdelimiter = @leefdelimiter if leefdelimiter.nil?
      leefdelimiter = self.class.get_config["leefdelimiter"][:default] if leefdelimiter == ""
    else
      leefdelimiter = LEEF_V1_DELIMITER
    end

    return leefdelimiter
  end

  private
  def get_leefdelimiter_value(leefdelimiter)
    if leefdelimiter.length > 1
      # delimiter can be expressed as hexadecimal value as 'x20' or '0x20'
      # or even in utf '0x1234'
      leefdelimiter = '0' + leefdelimiter if leefdelimiter[0] != '0'
      leefdelimiter = [leefdelimiter.to_i(16)].pack('U*')
    end

    return leefdelimiter
  end

  private
  # Escape pipes and backslashes in the header. Equal signs are ok.
  # Newlines are forbidden.
  def sanitize_header_field(value)
    output = ""

    value = value.to_s.gsub(/\r\n/, "\n")

    value.each_char{|c|
      case c
      when "\\", "|"
        output += "\\" + c
      when "\n", "\r"
        output += " "
      else
        output += c
      end
    }

    return output
  end

  # Keys must be made up of a single word, with no spaces
  # must be alphanumeric
  def sanitize_extension_key(value)
    value = value.to_s.gsub(/[^a-zA-Z0-9]/, "")
    return value
  end

  # Escape equal signs in the extensions. Canonicalize newlines.
  # LEEF spec leaves it up to us to choose \r or \n for newline.
  # We choose \n as the default.
  def sanitize_extension_val(value)
    output = ""

    value = value.to_s.gsub(/\r\n/, "\n")

    value.each_char{|c|
      case c
      when "\\", "="
        output += "\\" + c
      when "\n", "\r"
        output += "\\n"
      else
        output += c
      end
    }

    return output
  end

  def get_value(fieldname, event)
    val = event.get(fieldname)

    return nil if val.nil?

    case val
    when Array, Hash
      return "#{sanitize_extension_key(fieldname)}=#{sanitize_extension_val(val.to_json)}"
    when LogStash::Timestamp
      return "#{sanitize_extension_key(fieldname)}=#{val.to_s}"
    else
      return "#{sanitize_extension_key(fieldname)}=#{sanitize_extension_val(val)}"
    end
  end

  #def sanitize_severity(event, severity)
  #  severity = sanitize_header_field(event.sprintf(severity)).strip
  #  severity = self.class.get_config["severity"][:default] unless valid_severity?(severity)
  #  severity = severity.to_i.to_s
  #end

  #def valid_severity?(sev)
  #  f = Float(sev)
    # check if it's an integer or a float with no remainder
    # and if the value is between 0 and 10 (inclusive)
  #  (f % 1 == 0) && f.between?(0,10)
  #rescue TypeError, ArgumentError
  #  false
  #end

end
