require 'uri'
require 'net/http'
require 'json'
require 'digest/md5'

class SearchProvider::Censys < SearchProvider::Provider
  def self.provider_name
    "Censys Search"
  end

  def self.options
    {}
  end

  def initialize(query, options={})
    super
    @censys_app_id = Rails.configuration.try(:censys_app_id)
    @censys_secret = Rails.configuration.try(:censys_secret)
  end

  def run
    page = 1
    pages = 0
    results = []
    loop do
      uri = URI.parse("https://www.censys.io/api/v1/search/ipv4")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Post.new(uri.request_uri, 'Content-Type' => 'application/json')
      request.body = {query: @query, page: page, fields:["ip","protocols", "443.https.tls.certificate.parsed.issuer.organization", "tags", "80.http.get.title"]}.to_json
      request.basic_auth(@censys_app_id, @censys_secret)
      response = http.request(request)
      if response.code == "200"
        search_results = JSON.parse(response.body)
        search_results['results'].each do |result|
          metadata = search_results['metadata']
	  pages = metadata['pages']
          hashPort = Digest::MD5.hexdigest(result['ip'].to_s+result['protocols'].join(", "))
          results <<
          {
            :title => result['ip'].to_s + ' | ' + result['443.https.tls.certificate.parsed.issuer.organization'].to_s  + ' | ' + result['tags'].to_s,
            :url => 'https://censys.io/ipv4/'+result['ip'].to_s+'?md5hostport='+hashPort ,
            :domain => "censys.io"
          }
        end
      end
      page = page + 1
      if page > pages.to_i
        break
      end
    end
    return results
  end
end