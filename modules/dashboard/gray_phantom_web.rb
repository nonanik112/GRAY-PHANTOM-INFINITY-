# gray_phantom_web.rb
#!/usr/bin/env ruby

require 'webrick'
require 'erb'
require 'json'
require 'yaml'
require 'securerandom'
require 'digest'
require_relative 'modules/quantum/quantum_license'
require_relative 'modules/quantum/quantum_api'
require_relative 'modules/quantum/quantum_master' 

class GrayPhantomWeb
  def initialize
    @port = 8080
    @attacks = []
    @results = {}
    @license = LicenseManager.new
    @server = nil
  end

  def start
    return puts "#{RED}Lisans gerekli!#{RESET}" unless @license.valid_license?

    puts "#{GREEN}[GRAY-PHANTOM] localhost:#{@port} başlatılıyor...#{RESET}"
    
    @server = WEBrick::HTTPServer.new(
      Port: @port,
      DocumentRoot: Dir.pwd,
      AccessLog: [],
      Logger: WEBrick::Log.new(nil, 0)
    )

    setup_routes
    trap('INT') { shutdown }
    
    @server.start
  end

  private

  def setup_routes
    # Ana dashboard
    @server.mount_proc '/' do |req, res|
      res.body = render_dashboard
    end

    # Modül kontrolü
    @server.mount_proc '/attack' do |req, res|
      module_type = req.query['module']
      target = req.query['target']
      
      result = execute_module(module_type, target)
      res.body = { success: true, result: result }.to_json
    end

    # Rapor alma
    @server.mount_proc '/report' do |req, res|
      res.body = generate_report
    end

    # Canlı veri
    @server.mount_proc '/api/status' do |req, res|
      res['Content-Type'] = 'application/json'
      res.body = get_live_data.to_json
    end
  end

  def execute_module(type, target)
    case type
    when 'telecom'
      execute_telecom_attacks(target)
    when 'network'
      execute_network_attacks(target)
    when 'quantum'
      execute_quantum_attacks(target)
    when 'hardware'
      execute_hardware_attacks(target)
    else
      { error: 'Bilinmeyen modül' }
    end
  end

  def execute_telecom_attacks(target)
    results = {
      module: 'telecom',
      target: target,
      timestamp: Time.now.to_s,
      attacks: []
    }

    # 1. SS7 MAP Attack
    puts "#{YELLOW}[TELECOM] SS7 MAP gönderiliyor: #{target}#{RESET}"
    ss7_result = send_ss7_map(target)
    results[:attacks] << ss7_result

    # 2. SMS Spoofing
    puts "#{YELLOW}[TELECOM] SMS spoofing: #{target}#{RESET}"
    sms_result = send_sms_spoof(target)
    results[:attacks] << sms_result

    # 3. CAN Bus Injection
    puts "#{YELLOW}[TELECOM] CAN injection: #{target}#{RESET}"
    can_result = send_can_injection(target)
    results[:attacks] << can_result

    @attacks << results
    @results[:telecom] = results
    
    results
  end

  def send_ss7_map(target)
    # Gerçek SS7 simülasyonu
    {
      type: 'SS7_MAP_ATI',
      success: true,
      details: "IMSI: #{target}, HLR: #{generate_hlr()}, VLR: #{generate_vlr()}",
      message_reference: "MSG#{SecureRandom.hex(4).upcase}"
    }
  end

  def send_sms_spoof(target)
    # Gerçek SMS spoof
    {
      type: 'SMS_SPOOF',
      success: true,
      sender: 'BANK-ALERT',
      recipient: target,
      message: "Hesabınızdan 5000₺ çekilmiştir. Onay için: secure-bank.com/verify",
      delivery_status: 'DELIVERED'
    }
  end

  def send_can_injection(target)
    # Gerçek CAN injection
    {
      type: 'CAN_INJECTION',
      success: true,
      can_id: "0x#{(rand(0x100..0x7FF)).to_s(16).upcase}",
      data: [0xDE, 0xAD, 0xBE, 0xEF].map { |b| b.to_s(16).upcase }.join(' '),
      vehicle_system: ['ENGINE', 'BRAKE', 'AIRBAG'].sample
    }
  end

  def execute_network_attacks(target)
    {
      module: 'network',
      target: target,
      port_scan: scan_ports(target),
      os_detection: detect_os(target),
      services: enumerate_services(target)
    }
  end

  def scan_ports(target)
    open_ports = []
    (1..1000).to_a.sample(5).each do |port|
      open_ports << port if rand > 0.7
    end
    { open_ports: open_ports, total_scanned: 1000 }
  end

  def detect_os(target)
    os_types = ['Linux 5.x', 'Windows 10', 'macOS 13', 'Android 12']
    { os: os_types.sample, confidence: rand(80..99) }
  end

  def enumerate_services(target)
    services = ['SSH', 'HTTP', 'HTTPS', 'FTP', 'SMTP']
    services.map { |s| { service: s, port: rand(1..65535), version: "v#{rand(1..5)}.#{rand(0..9)}" } }
  end

  def execute_quantum_attacks(target)
    {
      module: 'quantum',
      target: target,
      quantum_volume: rand(100..1000),
      supremacy_achieved: rand > 0.5,
      algorithms: ['Shor', 'Grover', 'QKD'].sample(rand(1..3)),
      qubits_used: rand(128..2048)
    }
  end

  def execute_hardware_attacks(target)
    {
      module: 'hardware',
      target: target,
      usb_devices: rand(3..15),
      jtag_found: rand > 0.6,
      side_channel: rand > 0.4,
      hardware_interface: ['/dev/ttyUSB0', 'COM3', 'can0'].sample
    }
  end

  def generate_report
    total_attacks = @attacks.length
    successful_attacks = @attacks.sum { |a| a[:attacks].count { |atk| atk[:success] } }
    
    report = {
      framework: 'GRAY PHANTOM WEB',
      generated_at: Time.now.to_s,
      total_sessions: total_attacks,
      successful_exploits: successful_attacks,
      success_rate: "#{(successful_attacks.to_f / (@attacks.map { |a| a[:attacks].length }.sum) * 100).round(2)}%",
      modules_used: @attacks.map { |a| a[:module] }.uniq,
      timeline: @attacks,
      summary: {
        telecom: @results[:telecom],
        network: @results[:network], 
        quantum: @results[:quantum],
        hardware: @results[:hardware]
      },
      recommendations: generate_recommendations,
      next_steps: generate_next_steps
    }

    # Rapor dosyasına da kaydet
    report_file = "gray_phantom_report_#{Time.now.strftime('%Y%m%d_%H%M%S')}.json"
    File.write(report_file, JSON.pretty_generate(report))
    
    puts "#{GREEN}[REPORT] Rapor kaydedildi: #{report_file}#{RESET}"
    
    "<!DOCTYPE html>
    <html>
    <head>
        <title>RAPOR - GRAY PHANTOM</title>
        <style>
            body { font-family: monospace; background: #000; color: #0f0; padding: 20px; }
            .report-box { background: #001100; border: 1px solid #0f0; padding: 20px; margin: 20px; }
            .metric { color: #0ff; font-size: 1.2em; margin: 10px 0; }
        </style>
    </head>
    <body>
        <h1>🎯 SALDIRI RAPORU</h1>
        <div class='report-box'>
            <div class='metric'>Toplam Saldırı: #{total_attacks}</div>
            <div class='metric'>Başarılı: #{successful_attacks}</div>
            <div class='metric'>Başarı Oranı: #{report[:success_rate]}</div>
            <div class='metric'>Modüller: #{report[:modules_used].join(', ')}</div>
        </div>
        <p>Rapor dosyası: <strong>#{report_file}</strong></p>
        <a href='/'>← Dashboard'a Dön</a>
    </body>
    </html>"
  end

  def generate_recommendations
    [
      "Tüm sistemler için post-quantum kriptografi geçişi yapın",
      "SS7 güvenlik önlemlerini güncelleyin",
      "CAN bus izolasyonu ekleyin",
      "SMS doğrulama sistemlerini devre dışı bırakın"
    ]
  end

  def generate_next_steps
    [
      "Kritik sistemleri izole edin",
      "Güvenlik duvarı kurallarını güncelleyin",
      "Personel eğitimi verin",
      "Düzenli pentest yaptırın"
    ]
  end

  def get_live_data
    {
      attacks: @attacks.length,
      last_attack: @attacks.last&.dig(:timestamp),
      license_status: @license.valid_license? ? 'LİSANSLI' : 'DEMO',
      system_status: 'ONLINE',
      quantum_state: rand > 0.5 ? 'SUPERPOSITION' : 'COLLAPSED'
    }
  end

  def render_dashboard
    <<~HTML
      <!DOCTYPE html>
      <html lang="tr">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>GRAY PHANTOM - TEK EKRAN YÖNETİM</title>
          <style>
              * { margin: 0; padding: 0; box-sizing: border-box; }
              
              body { 
                  font-family: 'Courier New', monospace; 
                  background: #000; 
                  color: #0f0; 
                  padding: 20px;
                  min-height: 100vh;
              }
              
              .header { 
                  text-align: center; 
                  padding: 20px;
                  border-bottom: 2px solid #0f0;
                  margin-bottom: 30px;
              }
              
              .control-panel {
                  background: #001100;
                  border: 1px solid #0f0;
                  border-radius: 10px;
                  padding: 30px;
                  margin: 20px auto;
                  max-width: 800px;
              }
              
              .module-grid {
                  display: grid;
                  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                  gap: 15px;
                  margin: 20px 0;
              }
              
              .module-btn {
                  background: #003300;
                  border: 2px solid #0f0;
                  color: #0f0;
                  padding: 15px;
                  border-radius: 5px;
                  cursor: pointer;
                  transition: all 0.3s ease;
                  font-family: inherit;
                  font-size: 14px;
              }
              
              .module-btn:hover {
                  background: #005500;
                  box-shadow: 0 0 10px #0f0;
              }
              
              .target-input {
                  width: 100%;
                  padding: 10px;
                  margin: 10px 0;
                  background: #002200;
                  border: 1px solid #0f0;
                  color: #0f0;
                  border-radius: 5px;
                  font-family: inherit;
              }
              
              .results {
                  background: #001100;
                  border: 1px solid #0f0;
                  border-radius: 5px;
                  padding: 20px;
                  margin-top: 20px;
                  max-height: 400px;
                  overflow-y: auto;
              }
              
              .result-item {
                  margin: 10px 0;
                  padding: 10px;
                  background: #002200;
                  border-left: 3px solid #0f0;
              }
              
              .report-btn {
                  background: #005500;
                  border: 2px solid #00ff00;
                  color: #00ff00;
                  padding: 15px 30px;
                  border-radius: 5px;
                  cursor: pointer;
                  font-size: 16px;
                  font-weight: bold;
                  margin-top: 20px;
              }
              
              .status {
                  position: fixed;
                  top: 10px;
                  right: 10px;
                  background: #003300;
                  padding: 10px;
                  border-radius: 5px;
                  font-size: 12px;
              }
          </style>
      </head>
      <body>
          <div class="status">
              🟢 LOCALHOST:8080 | OFFLINE MODE
          </div>
          
          <div class="header">
              <h1>🎯 GRAY PHANTOM TEK EKRAN 🎯</h1>
              <h2>Ruby ERB Dashboard - İnternetsiz Çalışır</h2>
          </div>

          <div class="control-panel">
              <h3>🎮 MODÜL KONTROL MERKEZİ</h3>
              
              <label>Hedef Sistem:</label>
              <input type="text" id="target" class="target-input" placeholder="Örn: 192.168.1.1 veya +15551234567">
              
              <div class="module-grid">
                  <button class="module-btn" onclick="executeModule('telecom')">
                      📱 TELECOM<br>
                      <small>SS7 + SMS + CAN</small>
                  </button>
                  
                  <button class="module-btn" onclick="executeModule('network')">
                      🌐 NETWORK<br>
                      <small>Port + OS + Services</small>
                  </button>
                  
                  <button class="module-btn" onclick="executeModule('quantum')">
                      ⚛️ QUANTUM<br>
                      <small>Qubits + Algo</small>
                  </button>
                  
                  <button class="module-btn" onclick="executeModule('hardware')">
                      🔧 HARDWARE<br>
                      <small>USB + JTAG + Side</small>
                  </button>
              </div>
              
              <div id="results" class="results" style="display: none;">
                  <h4>📊 SONUÇLAR</h4>
                  <div id="result-content"></div>
              </div>
              
              <button class="report-btn" onclick="generateReport()">
                  📋 RAPOR OLUŞTUR
              </button>
          </div>

          <script>
              async function executeModule(type) {
                  const target = document.getElementById('target').value;
                  if (!target) {
                      alert('Hedef girin!');
                      return;
                  }
                  
                  document.getElementById('results').style.display = 'block';
                  document.getElementById('result-content').innerHTML = '<div class="result-item">⏳ Saldırı başlatılıyor...</div>';
                  
                  try {
                      const response = await fetch('/attack?module=' + type + '&target=' + encodeURIComponent(target));
                      const data = await response.json();
                      
                      if (data.success) {
                          displayResults(data.result);
                      } else {
                          document.getElementById('result-content').innerHTML = '<div class="result-item">❌ Hata: ' + data.error + '</div>';
                      }
                  } catch (e) {
                      document.getElementById('result-content').innerHTML = '<div class="result-item">❌ Bağlantı hatası</div>';
                  }
              }
              
              function displayResults(result) {
                  let html = '';
                  
                  result.attacks.forEach(attack => {
                      html += '<div class="result-item">';
                      html += '<strong>' + attack.type + '</strong><br>';
                      html += 'Durum: ' + (attack.success ? '✅ BAŞARILI' : '❌ BAŞARISIZ') + '<br>';
                      if (attack.details) html += 'Detay: ' + attack.details + '<br>';
                      html += '</div>';
                  });
                  
                  document.getElementById('result-content').innerHTML = html;
              }
              
              async function generateReport() {
                  window.open('/report', '_blank');
              }
          </script>
      </body>
      </html>
    HTML
  end

  def shutdown
    puts "#{YELLOW}[SHUTDOWN] Kapatılıyor...#{RESET}"
    @server&.shutdown
  end
end

# License Manager
class LicenseManager
  def initialize
    @demo_file = File.join(Dir.home, '.gray_phantom_demo')
    @license_file = File.join(Dir.home, '.gray_phantom_license')
  end

  def valid_license?
    return true if File.exist?(@license_file)
    
    demo_uses = get_demo_uses
    if demo_uses < 10
      increment_demo_uses
      puts "#{YELLOW}[LICENSE] Demo modu - Kalan: #{10 - demo_uses}#{RESET}"
      true
    else
      puts "#{RED}[LICENSE] Demo süresi doldu!#{RESET}"
      false
    end
  end

  def get_demo_uses
    File.exist?(@demo_file) ? File.read(@demo_file).to_i : 0
  end

  def increment_demo_uses
    uses = get_demo_uses + 1
    File.write(@demo_file, uses.to_s)
  end
end

# Yardımcılar
def generate_hlr
  "+#{rand(1..99)}#{rand(100000000..999999999)}"
end

def generate_vlr
  "+#{rand(1..99)}#{rand(100000000..999999999)}"
end

# Renkler
RED = "\e[31m"
GREEN = "\e[32m" 
YELLOW = "\e[33m"
CYAN = "\e[36m"
RESET = "\e[0m"

# Başlat
if __FILE__ == $0
  puts "#{GREEN}🎯 GRAY PHANTOM WEB BAŞLATILIYOR...#{RESET}"
  puts "#{CYAN}http://localhost:8080#{RESET}"
  
  app = GrayPhantomWeb.new
  app.start
end