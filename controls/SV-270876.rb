control 'SV-270876' do
  title 'The container root filesystem must be mounted as read-only.'
  desc 'Any changes to a container must be made by rebuilding
                the image and redeploying the new container image. Once a container is running,
                changes to the root filesystem should not be needed, thus preserving the immutable
                nature of the container. Any attempts to change the root filesystem are usually
                malicious in nature and can be prevented by making the root filesystem
                read-only.'
  desc 'check', 'Review the container platform configuration to determine that the
                    root filesystem is mounted as read-only. If the container platform does not
                    enforce such access restrictions, this is a finding.'
  desc 'fix', 'Review and remove nonsystem containers previously
                created with read-write permissions. Configure the container platform to force the
                root filesystem to be mounted as read-only.'
  impact 0.5
  tag check_id: 'C-74911r1050647_chk'
  tag severity: 'medium'
  tag gid: 'V-270876'
  tag rid: 'SV-270876r1050649_rule'
  tag stig_id: 'SRG-APP-000380-CTR-000340'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-74812r1050648_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
  tag implementation_status: 'not-applicable'

  impact 0.0
  describe 'Read-only root filesystem: task-definition control — aws-ecs-fargate-baseline (N/A)' do
    subject { true }
    it { is_expected.to eq true }
  end
end
