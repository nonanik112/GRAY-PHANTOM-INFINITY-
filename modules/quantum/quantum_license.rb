# modules/quantum/quantum_license.rb
class QuantumLicense
  def initialize
    @quantum_license_file = File.join(Dir.home, '.gray_phantom_quantum_license')
    @hardware_fingerprint = generate_hardware_fingerprint
  end

  def valid_quantum_license?
    return true if File.exist?(@quantum_license_file)
    
    # Demo: 3 quantum kullanım hakkı
    demo_uses = get_demo_quantum_uses
    if demo_uses < 3
      increment_quantum_demo
      puts "#{YELLOW}[QUANTUM-LICENSE] Demo modu - Kalan: #{3 - demo_uses}#{RESET}"
      true
    else
      puts "#{RED}[QUANTUM-LICENSE] Quantum lisansı gerekli!#{RESET}"
      false
    end
  end

  def generate_hardware_fingerprint
    # Quantum hardware kontrolü
    cpu = `lscpu | grep 'Model name'`.strip
    quantum_device = detect_quantum_device
    
    Digest::SHA256.hexdigest("#{cpu}-#{quantum_device}")[0..16]
  end

  def detect_quantum_device
    # IBM Quantum cihazı var mı?
    if system("python3 -c 'import qiskit' 2>/dev/null")
      "IBM_QUANTUM_#{SecureRandom.hex(4)}"
    else
      "NO_QUANTUM_#{SecureRandom.hex(4)}"
    end
  end
end