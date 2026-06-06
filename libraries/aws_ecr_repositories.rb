# encoding: UTF-8
#
# aws_ecr_repositories — account-wide ECR repository inventory (ecr:DescribeRepositories,
# paginated). The scope source for the registry-layer controls.
#
#   describe aws_ecr_repositories do
#     its('repository_names') { should_not be_empty }
#   end

class AwsEcrRepositories < AwsResourceBase
  name "aws_ecr_repositories"
  desc "All ECR repositories in the account/region."
  example "
    describe aws_ecr_repositories do
      its('repository_names') { should include 'my-app' }
    end
  "

  attr_reader :repositories, :repository_names

  def initialize(opts = {})
    super(opts)
    @repositories = []
    @repository_names = []
    catch_aws_errors do
      next_token = nil
      loop do
        resp = @aws.ecr_client.describe_repositories(next_token: next_token, max_results: 100)
        Array(resp.repositories).each do |r|
          @repositories << r
          @repository_names << r.repository_name
        end
        next_token = resp.next_token
        break if next_token.nil? || next_token.to_s.empty?
      end
    end
  end

  def exists?
    !@repository_names.empty?
  end

  def to_s
    "ECR Repositories"
  end
end
