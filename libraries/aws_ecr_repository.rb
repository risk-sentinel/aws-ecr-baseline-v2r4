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

  # Lazily-fetched image inventory (DescribeImages, paginated): per-image digest, tags,
  # scan status, and finding-severity counts. Fetched only when a control needs it.
  def images
    return @images if defined?(@images)
    @images = []
    catch_aws_errors do
      next_token = nil
      loop do
        resp = @aws.ecr_client.describe_images(repository_name: @repository_name, next_token: next_token, max_results: 100)
        Array(resp.image_details).each do |d|
          summary = d.image_scan_findings_summary
          @images << {
            digest:          d.image_digest,
            tags:            Array(d.image_tags),
            scan_status:     d.image_scan_status&.status.to_s,
            severity_counts: (summary && summary.finding_severity_counts) || {},
          }
        end
        next_token = resp.next_token
        break if next_token.nil? || next_token.to_s.empty?
      end
    end
    @images
  end

  # Image digests/tags that violate the scan gate: fail-closed — an image whose scan is
  # not COMPLETE counts as a violation (unscanned == unproven == non-compliant), as does
  # any image carrying findings above the tolerated severity ceiling.
  def scan_gate_violations(ceiling)
    rank = %w[INFORMATIONAL LOW MEDIUM HIGH CRITICAL]
    idx  = rank.index(ceiling.to_s.upcase) || rank.index("HIGH")
    disallowed = rank[(idx + 1)..] || []
    images.select do |im|
      next true unless im[:scan_status] == "COMPLETE" # fail-closed: unscanned == violation
      counts = im[:severity_counts] || {}
      disallowed.sum { |s| counts[s].to_i + counts[s.to_sym].to_i } > 0
    end.map { |im| im[:tags].first || im[:digest] }
  end

  SBOM_MEDIA = /spdx|cyclonedx|in-toto|\bsbom\b|bom/i.freeze

  # Images missing a signature and/or an SBOM referrer (supply-chain gaps). Fail-closed:
  # an unsigned image, or one without an attached SBOM, is a gap. Returns labels.
  def supply_chain_gaps
    images.map do |im|
      miss = []
      miss << "unsigned" unless image_signed?(im[:digest])
      miss << "no-SBOM"  unless image_has_sbom?(im[:digest])
      miss.empty? ? nil : "#{im[:tags].first || im[:digest][0, 16]}: #{miss.join('+')}"
    end.compact
  end

  private

  def image_signed?(digest)
    !Array(@aws.ecr_client.describe_image_signing_status(
      repository_name: @repository_name, image_id: { image_digest: digest }
    ).signing_statuses).empty?
  rescue StandardError
    false
  end

  def image_has_sbom?(digest)
    refs = []
    token = nil
    loop do
      resp = @aws.ecr_client.list_image_referrers(repository_name: @repository_name, subject_id: { image_digest: digest }, next_token: token)
      refs.concat(Array(resp.referrers))
      token = resp.next_token
      break if token.nil? || token.to_s.empty?
    end
    refs.any? { |r| %i[artifact_media_type artifact_type media_type].any? { |m| r.respond_to?(m) && r.public_send(m).to_s =~ SBOM_MEDIA } }
  rescue StandardError
    false
  end

  public

  def to_s
    "ECR Repository #{@repository_name}"
  end
end
