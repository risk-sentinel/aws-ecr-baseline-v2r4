control 'SV-233102' do
 title 'The container platform must obscure feedback of authentication information during
 the authentication process to protect the information from possible exploitation/use
 by unauthorized individuals.'
 desc 'To prevent the compromise of authentication
 information such as passwords during the authentication process, the feedback from
 the container platform and its components, e.g., runtime, registry, and keystore,
 must not provide any information that would allow an unauthorized user to compromise
 the authentication mechanism. Obfuscation of user-provided information when typed is
 a method used in addressing this risk. Displaying asterisks when a user types in a
 password is an example of obscuring feedback of authentication
 information.'
 desc 'check', "Review container platform documentation and configuration to
 determine if any interfaces that are provided for authentication purposes
 display the user's password when it is typed into the data entry field. If
 authentication information is not obfuscated when entered, this is a finding."
 desc 'fix', 'Configure the container platform to obscure
 feedback of authentication information during the authentication process to protect
 the information from possible exploitation/use by unauthorized individuals.'
 impact 0.5
 tag check_id: 'C-36038r601736_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233102'
 tag rid: 'SV-233102r961047_rule'
 tag stig_id: 'SRG-APP-000178-CTR-000470'
 tag gtitle: 'SRG-APP-000178'
 tag fix_id: 'F-36006r600794_fix'
 tag 'documentable'
 tag cci: ['CCI-000206']
 tag nist: ['IA-6']
 tag nist_r4: ['IA-6']
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
