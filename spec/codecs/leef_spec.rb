# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/leef"
require "logstash/event"
require "json"

describe LogStash::Codecs::LEEF do
  subject do
    next LogStash::Codecs::LEEF.new
  end

  context "#encode" do
    subject(:codec) { LogStash::Codecs::LEEF.new }

    let(:results)   { [] }

    it "should not fail if fields is nil" do
      codec.on_event{|data, newdata| results << newdata}
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^LEEF:1.0\|Elastic\|Logstash\|2.3.3\|Logstash\|$/m)
    end

    it "should assert all header fields are present" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^LEEF:1.0\|Elastic\|Logstash\|2.3.3\|Logstash\|$/m)
    end

    it "should use default values for empty header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = ""
      codec.product = ""
      codec.version = ""
      codec.eventid = ""
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^LEEF:1.0\|Elastic\|Logstash\|2.3.3\|Logstash\|$/m)
    end

    it "should use configured values for header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = "vendor"
      codec.product = "product"
      codec.version = "2.0"
      codec.eventid = "eventid"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^LEEF:1.0\|vendor\|product\|2.0\|eventid\|$/m)
    end

    it "should use sprintf for header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = "%{vendor}"
      codec.product = "%{product}"
      codec.version = "%{version}"
      codec.eventid = "%{eventid}"
      codec.fields = []
      event = LogStash::Event.new("vendor" => "vendor", "product" => "product", "version" => "2.0", "eventid" => "eventid")
      codec.encode(event)
      expect(results.first).to match(/^LEEF:1.0\|vendor\|product\|2.0\|eventid\|$/m)
    end

    it "should append fields as key/value pairs in leef extension part" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo", "bar" ]
      event = LogStash::Event.new("foo" => "foo value", "bar" => "bar value")
      codec.encode(event)
      expect(results.first).to match(/^LEEF:1.0\|Elastic\|Logstash\|2.3.3\|Logstash\|foo=foo value	bar=bar value$/m)
    end

    it "should ignore fields in fields if not present in event" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo", "bar", "baz" ]
      event = LogStash::Event.new("foo" => "foo value", "baz" => "baz value")
      codec.encode(event)
      expect(results.first).to match(/^LEEF:1.0\|Elastic\|Logstash\|2.3.3\|Logstash\|foo=foo value	baz=baz value$/m)
    end

    it "should sanitize header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = "ven\ndor"
      codec.product = "pro|duct"
      codec.version = "ver\\sion"
      codec.eventid = "event\rid"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^LEEF:1.0\|ven dor\|pro\\\|duct\|ver\\\\sion\|event id\|$/m)
    end

    it "should sanitize extension keys" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "f o\no", "@b-a_r" ]
      event = LogStash::Event.new("f o\no" => "foo value", "@b-a_r" => "bar value")
      codec.encode(event)
      expect(results.first).to match(/^LEEF:1.0\|Elastic\|Logstash\|2.3.3\|Logstash\|foo=foo value	bar=bar value$/m)
    end

    it "should sanitize extension values" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo", "bar", "baz" ]
      event = LogStash::Event.new("foo" => "foo\\value\n", "bar" => "bar=value\r")
      codec.encode(event)
      expect(results.first).to match(/^LEEF:1.0\|Elastic\|Logstash\|2.3.3\|Logstash\|foo=foo\\\\value\\n	bar=bar\\=value\\n$/m)
    end

    it "should encode a hash value" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => { "bar" => "bar value", "baz" => "baz value" })
      codec.encode(event)
      foo = results.first[/^LEEF:1.0\|Elastic\|Logstash\|2.3.3\|Logstash\|foo=(.*)$/, 1]
      expect(foo).not_to be_nil
      foo_hash = JSON.parse(foo)
      expect(foo_hash).to eq({"bar" => "bar value", "baz" => "baz value"})
    end

    it "should encode an array value" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => [ "bar", "baz" ])
      codec.encode(event)
      foo = results.first[/^LEEF:1.0\|Elastic\|Logstash\|2.3.3\|Logstash\|foo=(.*)$/, 1]
      expect(foo).not_to be_nil
      foo_array = JSON.parse(foo)
      expect(foo_array).to eq(["bar", "baz"])
    end

    it "should encode a hash in an array value" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => [ { "bar" => "bar value" }, "baz" ])
      codec.encode(event)
      foo = results.first[/^LEEF:1.0\|Elastic\|Logstash\|2.3.3\|Logstash\|foo=(.*)$/, 1]
      expect(foo).not_to be_nil
      foo_array = JSON.parse(foo)
      expect(foo_array).to eq([{"bar" => "bar value"}, "baz"])
    end

    it "should encode a LogStash::Timestamp" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => LogStash::Timestamp.new)
      codec.encode(event)
      expect(results.first).to match(/^LEEF:1.0\|Elastic\|Logstash\|2.3.3\|Logstash\|foo=[0-9TZ.:-]+$/m)
    end

  end

  context "sanitize header field" do
    subject(:codec) { LogStash::Codecs::LEEF.new }

    it "should sanitize" do
      expect(codec.send(:sanitize_header_field, "foo")).to be == "foo"
      expect(codec.send(:sanitize_header_field, "foo\nbar")).to be == "foo bar"
      expect(codec.send(:sanitize_header_field, "foo\rbar")).to be == "foo bar"
      expect(codec.send(:sanitize_header_field, "foo\r\nbar")).to be == "foo bar"
      expect(codec.send(:sanitize_header_field, "foo\r\nbar\r\nbaz")).to be == "foo bar baz"
      expect(codec.send(:sanitize_header_field, "foo\\bar")).to be == "foo\\\\bar"
      expect(codec.send(:sanitize_header_field, "foo|bar")).to be == "foo\\|bar"
      expect(codec.send(:sanitize_header_field, "foo=bar")).to be == "foo=bar"
      expect(codec.send(:sanitize_header_field, 123)).to be == "123" # Input value is a Fixnum
      expect(codec.send(:sanitize_header_field, 123.123)).to be == "123.123" # Input value is a Float
      expect(codec.send(:sanitize_header_field, [])).to be == "[]" # Input value is an Array
      expect(codec.send(:sanitize_header_field, {})).to be == "{}" # Input value is a Hash
    end
  end

  context "sanitize extension key" do
    subject(:codec) { LogStash::Codecs::LEEF.new }

    it "should sanitize" do
      expect(codec.send(:sanitize_extension_key, " foo ")).to be == "foo"
      expect(codec.send(:sanitize_extension_key, " FOO 123 ")).to be == "FOO123"
      expect(codec.send(:sanitize_extension_key, "foo\nbar\rbaz")).to be == "foobarbaz"
      expect(codec.send(:sanitize_extension_key, "Foo_Bar\r\nBaz")).to be == "FooBarBaz"
      expect(codec.send(:sanitize_extension_key, "foo-@bar=baz")).to be == "foobarbaz"
      expect(codec.send(:sanitize_extension_key, "[foo]|bar.baz")).to be == "foobarbaz"
      expect(codec.send(:sanitize_extension_key, 123)).to be == "123" # Input value is a Fixnum
      expect(codec.send(:sanitize_extension_key, 123.123)).to be == "123123" # Input value is a Float, "." is not allowed and therefore removed
      expect(codec.send(:sanitize_extension_key, [])).to be == "" # Input value is an Array, "[" and "]" are not allowed and therefore removed
      expect(codec.send(:sanitize_extension_key, {})).to be == "" # Input value is a Hash, "{" and "}" are not allowed and therefore removed
    end
  end

  context "sanitize extension value" do
    subject(:codec) { LogStash::Codecs::LEEF.new }

    it "should sanitize" do
      expect(codec.send(:sanitize_extension_val, "foo")).to be == "foo"
      expect(codec.send(:sanitize_extension_val, "foo\nbar")).to be == "foo\\nbar"
      expect(codec.send(:sanitize_extension_val, "foo\rbar")).to be == "foo\\nbar"
      expect(codec.send(:sanitize_extension_val, "foo\r\nbar")).to be == "foo\\nbar"
      expect(codec.send(:sanitize_extension_val, "foo\r\nbar\r\nbaz")).to be == "foo\\nbar\\nbaz"
      expect(codec.send(:sanitize_extension_val, "foo\\bar")).to be == "foo\\\\bar"
      expect(codec.send(:sanitize_extension_val, "foo|bar")).to be == "foo|bar"
      expect(codec.send(:sanitize_extension_val, "foo=bar")).to be == "foo\\=bar"
      expect(codec.send(:sanitize_extension_val, 123)).to be == "123" # Input value is a Fixnum
      expect(codec.send(:sanitize_extension_val, 123.123)).to be == "123.123" # Input value is a Float
      expect(codec.send(:sanitize_extension_val, [])).to be == "[]" # Input value is an Array
      expect(codec.send(:sanitize_extension_val, {})).to be == "{}" # Input value is a Hash
    end
  end

  context "#decode" do
    let (:message) { "LEEF:1.0|security|threatmanager|1.0|100|src=10.0.0.192 dst=12.121.122.82 spt=1232" }

    def validate(e) 
      insist { e.is_a?(LogStash::Event) }
      insist { e.get('leef_version') } == "1.0"
      insist { e.get('leef_device_version') } == "1.0"
      insist { e.get('leef_eventid') } == "100"
    end

    it "should parse the leef headers" do
      subject.decode(message) do |e|
        validate(e)
        ext = e.get('leef_ext')
        insist { e.get("leef_vendor") } == "security"
        insist { e.get("leef_product") } == "threatmanager"
      end
    end

    it "should parse the leef body" do
      subject.decode(message) do |e|
        ext = e.get('leef_ext')
        insist { ext['src'] } == "10.0.0.192"
        insist { ext['dst'] } == "12.121.122.82"
        insist { ext['spt'] } == "1232"
      end
    end

    let (:no_ext) { "LEEF:1.0|security|threatmanager|1.0|100|" }
    it "should be OK with no extension dictionary" do
      subject.decode(no_ext) do |e|
        validate(e)
        insist { e.get("leef_ext") } == nil
      end 
    end

    let (:missing_headers) { "LEEF:1.0|||1.0|100|src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "should be OK with missing LEEF headers (multiple pipes in sequence)" do
      subject.decode(missing_headers) do |e|
        validate(e)
        insist { e.get("leef_vendor") } == ""
        insist { e.get("leef_product") } == ""
      end 
    end

    let (:leading_whitespace) { "LEEF:1.0|security|threatmanager|1.0|100| src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "should strip leading whitespace from the message" do
      subject.decode(leading_whitespace) do |e|
        validate(e)
      end 
    end

    let (:escaped_pipes) { 'LEEF:1.0|security|threatmanager|1.0|100|moo=this\|has an escaped pipe' }
    it "should be OK with escaped pipes in the message" do
      subject.decode(escaped_pipes) do |e|
        ext = e.get('leef_ext')
        insist { ext['moo'] } == 'this\|has an escaped pipe'
      end 
    end

    let (:pipes_in_message) {'LEEF:1.0|security|threatmanager|1.0|100|moo=this|has an pipe'}
    it "should be OK with not escaped pipes in the message" do
      subject.decode(pipes_in_message) do |e|
        ext = e.get('leef_ext')
        insist { ext['moo'] } == 'this|has an pipe'
      end
    end

    let (:escaped_equal_in_message) {'LEEF:1.0|security|threatmanager|1.0|100|moo=this \=has escaped \= equals\='}
    it "should be OK with escaped equal in the message" do
      subject.decode(escaped_equal_in_message) do |e|
        ext = e.get('leef_ext')
        insist { ext['moo'] } == 'this =has escaped = equals='
      end
    end

    let (:escaped_backslash_in_header) {'LEEF:1.0|secu\\\\rity|threat\\\\manager|1.\\\\0|10\\\\0|'}
    it "should be OK with escaped backslash in the headers" do
      subject.decode(escaped_backslash_in_header) do |e|
        insist { e.get("leef_version") } == '1.0'
        insist { e.get("leef_vendor") } == 'secu\\rity'
        insist { e.get("leef_product") } == 'threat\\manager'
        insist { e.get("leef_device_version") } == '1.\\0'
        insist { e.get("leef_eventid") } == '10\\0'
      end
    end

    let (:escaped_backslash_in_header_edge_case) {'LEEF:1.0|security\\\\\\||threatmanager\\\\|1.0|100|'}
    it "should be OK with escaped backslash in the headers (edge case: escaped slash in front of pipe)" do
      subject.decode(escaped_backslash_in_header_edge_case) do |e|
        validate(e)
        insist { e.get("leef_vendor") } == 'security\\|'
        insist { e.get("leef_product") } == 'threatmanager\\'
      end
    end

  #  let (:escaped_pipes_in_header) {'LEEF:1.0|secu\\|rity|threatmanager\\||1.\\|0|10\\|0|'}
  #  it "should be OK with escaped pipes in the headers" do
  #    subject.decode(escaped_pipes_in_header) do |e|
  #      insist { e.get("leef_version") } == '0'
  #      insist { e.get("leef_vendor") } == 'secu|rity'
  #      insist { e.get("leef_product") } == 'threatmanager|'
  #      insist { e.get("leef_device_version") } == '1.|0'
  #      insist { e.get("leef_eventid") } == '10|0'
  #    end
  #  end
	
    let (:escaped_pipes_in_header) {'LEEF:1.0|secu\\|rity|threatmanager\\||1.\\|0|10\\|0|'}
    it "should be OK with escaped pipes in the headers" do
      subject.decode(escaped_pipes_in_header) do |e|
        insist { e.get("leef_version") } == '1.0'
        insist { e.get("leef_vendor") } == 'secu|rity'
        insist { e.get("leef_product") } == 'threatmanager|'
        insist { e.get("leef_device_version") } == '1.|0'
        insist { e.get("leef_eventid") } == '10|0'
      end
    end

    let (:escaped_backslash_in_message) {'LEEF:1.0|security|threatmanager|1.0|100|moo=this \\\\has escaped \\\\ backslashs\\\\'}
    it "should be OK with escaped backslashs in the message" do
      subject.decode(escaped_backslash_in_message) do |e|
        ext = e.get('leef_ext')
        insist { ext['moo'] } == 'this \\has escaped \\ backslashs\\'
      end
    end

    let (:equal_in_header) {'LEEF:1.0|security|threatmanager=equal|1.0|100|'}
    it "should be OK with equal in the headers" do
      subject.decode(equal_in_header) do |e|
        validate(e)
        insist { e.get("leef_product") } == "threatmanager=equal"
      end
    end

    let (:syslog) { "Syslogdate Sysloghost LEEF:1.0|security|threatmanager|1.0|100|src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "Should detect headers before LEEF starts" do
      subject.decode(syslog) do |e|
        validate(e)
        insist { e.get('syslog') } == 'Syslogdate Sysloghost'
      end 
    end
  end

  context "encode and decode" do
    subject(:codec) { LogStash::Codecs::LEEF.new }

    let(:results)   { [] }

    it "should return an equal event if encoded and decoded again" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = "%{leef_vendor}"
      codec.product = "%{leef_product}"
      codec.version = "%{leef_device_version}"
      codec.eventid = "%{leef_eventid}"
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("leef_vendor" => "vendor", "leef_product" => "product", "leef_device_version" => "2.0", "leef_eventid" => "eventid", "foo" => "bar")
      codec.encode(event)
      codec.decode(results.first) do |e|
        expect(e.get('leef_vendor')).to be == event.get('leef_vendor')
        expect(e.get('leef_product')).to be == event.get('leef_product')
        expect(e.get('leef_device_version')).to be == event.get('leef_device_version')
        expect(e.get('leef_eventid')).to be == event.get('leef_eventid')
        expect(e.get('[leef_ext][foo]')).to be == event.get('foo')
      end
    end
  end

end
