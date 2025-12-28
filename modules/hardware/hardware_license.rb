# modules/hardware/hardware_license.rb
class HardwareLicense
  def initialize
    @hardware_license_file = File.join(Dir.home, '.gray_phantom_hardware_license')
    @hardware_fingerprint = generate_hardware_fingerprint
  end

  def valid_hardware_license?
    return true if File.exist?(@hardware_license_file)
    
    # Demo: 3 hardware kullanım hakkı
    demo_uses = get_hardware_demo_uses
    if demo_uses < 3
      increment_hardware_demo
      puts "#{YELLOW}[HARDWARE-LICENSE] Demo modu - Kalan: #{3 - demo_uses}#{RESET}"
      true
    else
      puts "#{RED}[HARDWARE-LICENSE] Hardware lisansı gerekli!#{RESET}"
      false
    end
  end

  def generate_hardware_fingerprint
    # Donanım fingerprint'i
    cpu = `cat /proc/cpuinfo | grep 'model name' | head -1`.strip
    usb_devices = `lsusb | wc -l`.strip
    
    Digest::SHA256.hexdigest("#{cpu}-#{usb_devices}-#{rand(1000..9999)}")[0..24]
  end

  def check_hardware_compatibility
    compatible = []
    
    compatible << "GPS-SDR" if system("which hackrf_info >/dev/null 2>&1") || system("which rtl_test >/dev/null 2>&1")
    compatible << "JTAG-USB" if system("which openocd >/dev/null 2>&1") || system("which JLinkExe >/dev/null 2>&1")
    compatible << "RFID-USB" if system("which python3 -c 'import pn532' >/dev/null 2>&1")
    compatible << "RTL-SDR" if system("which rtl_test >/dev/null 2>&1")
    
    compatible
  end
end