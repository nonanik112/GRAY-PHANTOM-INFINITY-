# examples/automotive_example.rb
#!/usr/bin/env ruby

require_relative '../black_phantom_infinity'

puts "🚗 AUTOMOTIVE SECURITY EXAMPLE 🚗"

# Initialize automotive attack
framework = BlackPhantomInfinity.new('can0',
  can_interface: 'can0',
  obd_device: '/dev/ttyOBD'
)

puts "1. CAN bus attacks..."
framework.can_bus_attacks

puts "2. OBD-II exploitation..."
framework.obd_ii_exploitation

puts "3. Keyless entry attacks..."
framework.keyless_entry_attacks

puts "4. ECU hacking..."
framework.vehicle_ecu_hacking

puts "✅ Automotive security example complete!"