# modules/quantum/quantum_api.rb
class QuantumAPI
  def initialize(infinity_division)
    @infinity = infinity_division
    @license = LicenseManager.new
  end

  def handle_quantum_attack(request)
    return {error: 'Lisans gerekli'} unless @license.valid_license?
    
    data = JSON.parse(request.body)
    type = data['type']
    target = data['target']
    
    result = case type
    when 'shor'
      @infinity.real_quantum_shor_attack(target)
    when 'grover'
      @infinity.real_quantum_grover_attack(target)  
    when 'volume'
      @infinity.real_quantum_volume_test(target)
    when 'supremacy'
      @infinity.real_quantum_supremacy_attacks(target)
    end
    
    result.to_json
  end
end