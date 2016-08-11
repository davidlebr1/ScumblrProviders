require 'digest/md5'
require 'shodan'

class SearchProvider::Shodan < SearchProvider::Provider

  def self.provider_name
    "Shodan Search"
  end

  def initialize(query, options={})
    super

    @shodan_api_key = Rails.configuration.try(:shodan_api_key)
  end


  def run
    results = []
    api = Shodan::Shodan.new(@shodan_api_key)
    result = api.search(@query)
    result['matches'].each do |host|
	hostResult = api.host(host['ip_str'])
	hashPort = Digest::MD5.hexdigest(host['ip_str'].to_s+hostResult['ports'].join(", "))
	results <<
	{
	  :title => host['hostnames'].join("") + ' | ' + host['isp'].to_s  + ' | ' + hostResult['ports'].join(", "),
          :url => 'https://www.shodan.io/host/'+host['ip_str'].to_s+'?md5hostport='+hashPort.to_s,
          :domain => 'shodan.io'
	}
    end
    return results
  end
end