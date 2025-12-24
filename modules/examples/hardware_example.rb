# examples/hardware_example.rb
#!/usr/bin/env ruby

require_relative '../black_phantom_infinity'

puts "🔧 HARDWARE EXPLOITATION EXAMPLE 🔧"

# Initialize hardware attack
framework = BlackPhantomInfinity.new('hardware.target',
  hardware_interface: '/dev/ttyUSB0',
  sdr_device: 'rtl2832'
)

puts "1. USB HID attacks..."
framework.usb_hid_attacks

puts "2. Side-channel attacks..."
framework.side_channel_attacks

puts "3. JTAG debugging..."
framework.jtag_swd_debugging

puts "4. RFID/NFC cloning..."
framework.rfid_nfc_cloning

puts "✅ Hardware exploitation example complete!"