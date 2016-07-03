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
        expect(e['leef_vendor']).to be == event['leef_vendor']
        expect(e['leef_product']).to be == event['leef_product']
        expect(e['leef_device_version']).to be == event['leef_device_version']
        expect(e['leef_eventid']).to be == event['leef_eventid']
        expect(e['leef_ext']['foo']).to be == event['foo']
      end
    end
  end

end
