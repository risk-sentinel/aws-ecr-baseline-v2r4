# encoding: UTF-8
#
# aws_ecr_repository — posture of a single ECR repository: scan-on-push, image-tag
# mutability, encryption (KMS vs AES256), repository policy (parsed for public /
# cross-account access), and lifecycle-policy presence.
#
#   describe aws_ecr_repository(repository_name: 'app') do
#     it { should be_scan_on_push }
#     its('image_tag_mutability') { should cmp 'IMMUTABLE' }
#   end
#
# RepositoryPolicyNotFound / LifecyclePolicyNotFound are EXPECTED when unset and are
# rescued (not treated as resource errors) so the policy/lifecycle predicates report
# "absent" rather than failing the whole resource.

require "json"

class AwsEcrRepository < AwsResourceBase
  name "aws_ecr_repository"
  desc "Configuration + policy posture of a single ECR repository."
  example "
    describe aws_ecr_repository(repository_name: 'app') do
      it { should be_immutable }
    end
  "

  attr_reader :repository_name, :repository_arn, :registry_id,
              :image_tag_mutability, :encryption_type, :kms_key,
              :policy_text, :lifecycle_policy_text

  def initialize(opts = {})
    opts = { repository_name: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: %i[repository_name])
    @repository_name = opts[:repository_name]
    @exists = false

    catch_aws_errors do
      resp = @aws.ecr_client.describe_repositories(repository_names: [@repository_name])
      repo = resp.repositories.first
      next if repo.nil?

      @exists               = true
      @repository_arn       = repo.repository_arn
      @registry_id          = repo.registry_id
      @image_tag_mutability = repo.image_tag_mutability
      @scan_on_push         = repo.image_scanning_configuration&.scan_on_push == true
      enc                   = repo.encryption_configuration
      @encryption_type      = enc&.encryption_type
      @kms_key              = enc&.kms_key

      @policy_text = begin
        @aws.ecr_client.get_repository_policy(repository_name: @repository_name).policy_text
      rescue Aws::ECR::Errors::RepositoryPolicyNotFoundException
        nil
      end

      @lifecycle_policy_text = begin
        @aws.ecr_client.get_lifecycle_policy(repository_name: @repository_name).lifecycle_policy_text
      rescue Aws::ECR::Errors::LifecyclePolicyNotFoundException
        nil
      end
    end
  end

  def exists?
    @exists == true
  end

  def scan_on_push?
    @scan_on_push == true
  end

  def immutable?
    @image_tag_mutability.to_s == "IMMUTABLE"
  end

  def kms_encrypted?
    @encryption_type.to_s == "KMS"
  end

  def has_repository_policy?
    !@policy_text.to_s.empty?
  end

  def has_lifecycle_policy?
    !@lifecycle_policy_text.to_s.empty?
  end

  # True if the repository policy grants access to a principal outside this account
  # (a public "*" principal, or a cross-account IAM ARN). Used by the deny-all /
  # permit-by-exception + least-privilege registry controls.
  def policy_allows_external?
    return false if @policy_text.to_s.empty?
    doc = (JSON.parse(@policy_text) rescue nil)
    return false if doc.nil?
    Array(doc["Statement"]).any? do |st|
      next false unless st["Effect"] == "Allow"
      pr = st["Principal"]
      principals = pr.is_a?(Hash) ? Array(pr["AWS"]) : Array(pr)
      principals.map(&:to_s).any? do |p|
        p == "*" || (p =~ /arn:aws[^:]*:iam::(\d{12}):/ && Regexp.last_match(1) != @registry_id.to_s)
      end
    end
  end

  def to_s
    "ECR Repository #{@repository_name}"
  end
end
