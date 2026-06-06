control 'SV-263588' do
 title 'The container platform must alert organization-defined personnel or roles upon
 detection of unauthorized access, modification, or deletion of audit information.'
 desc 'Audit information includes all information needed to
 successfully audit system activity, such as audit records, audit log settings, audit
 reports, and personally identifiable information. Audit logging tools are those
 programs and devices used to conduct system audit and logging activities. Protection
 of audit information focuses on technical protection and limits the ability to
 access and execute audit logging tools to authorized individuals. Physical
 protection of audit information is addressed by both media protection controls and
 physical and environmental protection
 controls.'
 desc 'check', 'Verify the container platform is configured to alert
 organization-defined personnel or roles upon detection of unauthorized access,
 modification, or deletion of audit information. If the container platform is not
 configured to alert organization-defined personnel or roles upon detection of
 unauthorized access, modification, or deletion of audit information, this is a
 finding.'
 desc 'fix', 'Configure the container platform to alert
 organization-defined personnel or roles upon detection of unauthorized access,
 modification, or deletion of audit information.'
 impact 0.5
 tag check_id: 'C-67488r982456_chk'
 tag severity: 'medium'
 tag gid: 'V-263588'
 tag rid: 'SV-263588r982457_rule'
 tag stig_id: 'SRG-APP-000795-CTR-000130'
 tag gtitle: 'SRG-APP-000795'
 tag fix_id: 'F-67396r981903_fix'
 tag 'documentable'
 tag cci: ['CCI-003831']
 tag nist: ['AU-9 b']
 tag implementation_status: 'alternative'
 tag attestation_category: 'operational'

 impact 0.5
 describe 'operational/governance control (SAF attestation)' do
 skip 'organizational/operational control (alerting, governance policy, or password-breach tooling) — not API-assertable; supply a SAF attestation.'
 end
end
