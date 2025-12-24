# examples/quantum_example.rb
#!/usr/bin/env ruby

require_relative '../black_phantom_infinity'

puts "🌌 QUANTUM ATTACK EXAMPLE 🌌"

# Initialize quantum-enabled attack
framework = BlackPhantomInfinity.new('192.168.1.100',
  quantum_backend: 'local_simulation',
  quantum_qubits: 1024
)

puts "1. Executing quantum reconnaissance..."
framework.infinity_quantum_reconnaissance

puts "2. Testing quantum algorithms..."
# Test Shor's algorithm on small RSA key
small_rsa = 15  # 3 * 5
factors = framework.quantum_shor_factorization(small_rsa)
puts "   Quantum factorization of #{small_rsa}: #{factors.inspect}"

puts "3. Grover's algorithm target discovery..."
targets = ['web_server', 'database', 'file_server', 'workstation']
optimal_targets = framework.quantum_grover_target_discovery(targets)
puts "   Optimal targets: #{optimal_targets.inspect}"

puts "4. Post-quantum crypto assessment..."
framework.post_quantum_crypto_assessment

puts "✅ Quantum attack example complete!"