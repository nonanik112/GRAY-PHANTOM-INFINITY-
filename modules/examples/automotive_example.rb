# examples/automotive_example.rb
#!/usr/bin/env ruby

require_relative '../black_phantom_infinity'
require 'socket'
require 'serialport'
require 'rtlsdr'
require 'hackrf'
require 'gpio'
require 'i2c'
require 'spi'
require 'chipwhisperer'

puts "🚗 AUTOMOTIVE SECURITY EXAMPLE - 40 MADDE EXTREME CRITICAL 🚗"
puts "💀 Gerçek CAN bus, ECU hacking, keyless entry, relay attack aktif"

# Initialize automotive attack
framework = BlackPhantomInfinity.new('can0',
  can_interface: 'can0',
  obd_device: '/dev/ttyOBD',
  hackrf_device: '/dev/hackrf0',
  chipwhisperer_device: '/dev/chipwhisperer'
)

puts "1. CAN bus attacks..."
framework.can_bus_attacks

puts "2. OBD-II exploitation..."
framework.obd_ii_exploitation

puts "3. Keyless entry attacks..."
framework.keyless_entry_attacks

puts "4. ECU hacking..."
framework.vehicle_ecu_hacking

puts "5. Physical attacks..."
framework.physical_attacks

puts "6. Advanced automotive exploits..."
framework.advanced_automotive_exploits

puts "✅ Automotive security example complete - 40 attacks executed!"