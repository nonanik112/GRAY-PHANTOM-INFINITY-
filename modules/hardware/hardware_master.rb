# modules/hardware/hardware_master.rb
class HardwareMaster
  def initialize(infinity_division)
    @infinity = infinity_division
    @license = HardwareLicense.new
  end

  def execute_all_hardware_modules(target)
    results = {}
    
    puts "#{GREEN}[HARDWARE-MASTER] Tüm hardware modülleri başlatılıyor...#{RESET}"
    
    # 1. GPS Spoofing
    results[:gps] = execute_real_gps_spoof(target)
    
    # 2. JTAG Exploitation
    results[:jtag] = execute_real_jtag_exploit(target)
    
    # 3. RFID/NFC
    results[:rfid] = execute_real_rfid_nfc(target)
    
    # 4. Side-Channel
    results[:side_channel] = execute_real_side_channel(target)
    
    # 5. USB Attacks
    results[:usb] = execute_real_usb_attacks(target)
    
    results
  end

  def execute_real_gps_spoof(target)
    log "[HARDWARE-MASTER] Real GPS spoof modülü çalışıyor"
    
    gps = GPSSpoofReal.new
    coord = parse_target_coordinates(target)
    
    gps.execute_real_gps_spoof(coord[:lat], coord[:lon], coord[:alt], coord[:speed])
  end

  def execute_real_jtag_exploit(target)
    log "[HARDWARE-MASTER] Real JTAG exploit modülü çalışıyor"
    
    jtag = JTAGReal.new
    jtag.execute_real_jtag_exploit(target)
  end

  def execute_real_rfid_nfc(target)
    log "[HARDWARE-MASTER] Real RFID/NFC modülü çalışıyor"
    
    rfid = RFIDNFCReal.new
    rfid.execute_real_rfid_nfc_attacks(target)
  end

  def execute_real_side_channel(target)
    log "[HARDWARE-MASTER] Real Side-Channel modülü çalışıyor"
    
    side = SideChannelReal.new
    side.execute_real_side_channel(target)
  end

  def execute_real_usb_attacks(target)
    log "[HARDWARE-MASTER] Real USB attacks modülü çalışıyor"
    
    usb = USBAttacksReal.new  # Yeni gerçek USB sınıfı
    usb.execute_real_usb_attacks(target)
  end
end