# encoding: UTF-8
#
# aws_ecr_registry_scanning — registry-level ECR scanning configuration
# (ecr:GetRegistryScanningConfiguration). BASIC = the built-in Clair-based scan;
# ENHANCED = Amazon Inspector deep OS + language-package scanning (the comprehensive,
# privileged scan). Registry-wide (one setting per account/region).
#
#   describe aws_ecr_registry_scanning do
#     it { should be_enhanced }
#   end

class AwsEcrRegistryScanning < AwsResourceBase
  name "aws_ecr_registry_scanning"
  desc "Registry-level ECR scanning configuration (basic vs enhanced/Inspector)."
  example "
    describe aws_ecr_registry_scanning do
      it { should be_enhanced }
    end
  "

  attr_reader :scan_type, :rules

  def initialize(opts = {})
    super(opts)
    @rules = []
    catch_aws_errors do
      cfg        = @aws.ecr_client.get_registry_scanning_configuration.scanning_configuration
      @scan_type = cfg.scan_type
      @rules     = Array(cfg.rules)
    end
  end

  # ENHANCED = Amazon Inspector continuous/on-push deep scanning.
  def enhanced?
    @scan_type.to_s == "ENHANCED"
  end

  def configured?
    !@scan_type.to_s.empty?
  end

  # Scan frequencies declared in the registry rules (e.g. SCAN_ON_PUSH, CONTINUOUS_SCAN).
  def scan_frequencies
    @rules.map { |r| r.respond_to?(:scan_frequency) ? r.scan_frequency : nil }.compact
  end

  def to_s
    "ECR Registry Scanning (#{@scan_type || 'unknown'})"
  end
end
