control 'SV-233127' do
 title 'The container platform must prohibit containers from accessing privileged
 resources.'
 desc 'Containers images instantiated within the container
 platform may request access to host system resources. Access to privileged resources
 can allow for unauthorized and unintended transfer of information, but in some
 cases, these resources may be needed for the service being offered by the container.
 By default, containers should be denied instantiation when privileged system
 resources are requested and granted only after approval has been given. When access
 to privileged resources is necessary for a container, a new policy for execution
 should be written for the container. The default behavior must not give containers
 privileged access to host system resources. Examples of system resources that should
 be protected are kernel namespaces and host system sensitive directories such as
 /etc and /usr. This requirement also applies to Zero Trust
 initiatives.'
 desc 'check', 'Review documentation and configuration to determine if the container
 platform disallows instantiation of containers trying to access host system
 privileged resources. If the container platform does not block containers
 requesting host system privileged resources, this is a finding.'
 desc 'fix', 'Configure the container platform to block
 instantiation of containers requesting access to host system-privileged resources.'
 impact 0.5
 tag check_id: 'C-36063r601752_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233127'
 tag rid: 'SV-233127r1137644_rule'
 tag stig_id: 'SRG-APP-000243-CTR-000595'
 tag gtitle: 'SRG-APP-000243'
 tag fix_id: 'F-36031r600869_fix'
 tag 'documentable'
 tag cci: ['CCI-001090']
 tag nist: ['SC-4']
 tag nist_r4: ['SC-4']
 tag implementation_status: 'inherited'
 tag inherited_from: 'aws-shared-responsibility'

 # AWS-managed: IAM identity internals / Fargate runtime / platform config (the cloud-provider authorization).
 ev = input('inherited_evidence_uri', value: '')
 ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
 max_age = input('leveraged_evidence_max_age_days', value: 365)
 impact 0.5
 if ev.to_s.empty?
 describe 'AWS-inherited authorization evidence' do
 skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base/inherited_evidence_uri to the cloud-provider authorization manifest, or supply a SAF attestation.'
 end
 else
 doc = document_attestation(ev, max_age_days: max_age)
 describe "AWS authorization evidence (#{ev})" do
 it('exists') { expect(doc.exists?).to eq(true) }
 it('current') { expect(doc.current?(max_age)).to eq(true) }
 end
 end
end
