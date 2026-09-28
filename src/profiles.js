'use strict';
// 客户端配置文件：Apple .mobileconfig、Windows PowerShell 脚本、Android strongSwan .sswan
const crypto = require('node:crypto');
const pki = require('./pki');
const { userNets } = require('./model');

const xml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const uuid = () => crypto.randomUUID().toUpperCase();
const psq = (s) => `'${String(s).replace(/'/g, "''")}'`; // PowerShell 单引号字符串

function ctx(state, user) {
  const s = state.settings;
  const full = s.users_full_tunnel === '1';
  return {
    host: s.public_host,
    name: s.vpn_name,
    full,
    routes: full ? [] : userNets(state),
    selfSigned: s.cert_mode !== 'custom',
    user,
  };
}

// ---------- Apple ----------
function mobileconfig(state, user, { p12, p12Password } = {}) {
  const c = ctx(state, user);
  const certMode = user.auth_type === 'cert';
  const caUuid = uuid();
  const p12Uuid = uuid();
  const vpnUuid = uuid();
  const saParams = `
        <dict>
          <key>EncryptionAlgorithm</key><string>AES-256</string>
          <key>IntegrityAlgorithm</key><string>SHA2-256</string>
          <key>DiffieHellmanGroup</key><integer>14</integer>
          <key>LifeTimeInMinutes</key><integer>1440</integer>
        </dict>`;

  const payloads = [];
  if (c.selfSigned) {
    payloads.push(`
    <dict>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadIdentifier</key><string>ipsec-panel.ca.${caUuid}</string>
      <key>PayloadUUID</key><string>${caUuid}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>${xml(pki.CA_CN)}</string>
      <key>PayloadContent</key><data>${pki.caDer().toString('base64')}</data>
    </dict>`);
  }
  if (certMode) {
    payloads.push(`
    <dict>
      <key>PayloadType</key><string>com.apple.security.pkcs12</string>
      <key>PayloadIdentifier</key><string>ipsec-panel.p12.${p12Uuid}</string>
      <key>PayloadUUID</key><string>${p12Uuid}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>${xml(user.username)}</string>
      <key>Password</key><string>${xml(p12Password)}</string>
      <key>PayloadContent</key><data>${p12.toString('base64')}</data>
    </dict>`);
  }
  const auth = certMode
    ? `
        <key>AuthenticationMethod</key><string>Certificate</string>
        <key>CertificateType</key><string>RSA</string>
        <key>PayloadCertificateUUID</key><string>${p12Uuid}</string>
        <key>LocalIdentifier</key><string>${xml(user.username)}</string>
        <key>ExtendedAuthEnabled</key><integer>0</integer>`
    : `
        <key>AuthenticationMethod</key><string>None</string>
        <key>ExtendedAuthEnabled</key><integer>1</integer>
        <key>AuthName</key><string>${xml(user.username)}</string>
        <key>LocalIdentifier</key><string>${xml(user.username)}</string>`;

  payloads.push(`
    <dict>
      <key>PayloadType</key><string>com.apple.vpn.managed</string>
      <key>PayloadIdentifier</key><string>ipsec-panel.vpn.${vpnUuid}</string>
      <key>PayloadUUID</key><string>${vpnUuid}</string>
      <key>PayloadVersion</key><integer>1</integer>
      <key>PayloadDisplayName</key><string>${xml(c.name)}</string>
      <key>UserDefinedName</key><string>${xml(c.name)}</string>
      <key>VPNType</key><string>IKEv2</string>
      <key>IKEv2</key>
      <dict>
        <key>RemoteAddress</key><string>${xml(c.host)}</string>
        <key>RemoteIdentifier</key><string>${xml(c.host)}</string>
        <key>ServerCertificateCommonName</key><string>${xml(c.host)}</string>${
          c.selfSigned ? `\n        <key>ServerCertificateIssuerCommonName</key><string>${xml(pki.CA_CN)}</string>` : ''
        }${auth}
        <key>DeadPeerDetectionRate</key><string>Medium</string>
        <key>DisableMOBIKE</key><integer>0</integer>
        <key>DisableRedirect</key><integer>1</integer>
        <key>EnablePFS</key><integer>0</integer>
        <key>OnDemandEnabled</key><integer>0</integer>
        <key>IKESecurityAssociationParameters</key>${saParams}
        <key>ChildSecurityAssociationParameters</key>${saParams}
      </dict>
      <key>IPv4</key>
      <dict>
        <key>OverridePrimary</key><integer>${c.full ? 1 : 0}</integer>
      </dict>
    </dict>`);

  const rootUuid = uuid();
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>${payloads.join('')}
  </array>
  <key>PayloadDisplayName</key><string>${xml(c.name)} (${xml(user.username)})</string>
  <key>PayloadIdentifier</key><string>ipsec-panel.${rootUuid}</string>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>${rootUuid}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadRemovalDisallowed</key><false/>
</dict>
</plist>
`;
}

// ---------- Windows ----------
function windowsScript(state, user, { p12, p12Password } = {}) {
  const c = ctx(state, user);
  const certMode = user.auth_type === 'cert';
  const lines = [
    '# IPsec Panel 生成的 Windows IKEv2 VPN 一键配置脚本',
    `# 用户: ${user.username}`,
    '# 使用方法：右键“以管理员身份运行 PowerShell”，执行：',
    '#   powershell -ExecutionPolicy Bypass -File .\\这个文件.ps1',
    '$ErrorActionPreference = "Stop"',
    '',
    'if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {',
    '  Write-Host "请以管理员身份运行此脚本" -ForegroundColor Red; exit 1',
    '}',
    '',
    `$Name = ${psq(c.name)}`,
    `$Server = ${psq(c.host)}`,
    '$Tmp = Join-Path $env:TEMP ("ipsec-panel-" + [guid]::NewGuid().ToString())',
    'New-Item -ItemType Directory -Path $Tmp | Out-Null',
    '',
  ];
  if (c.selfSigned) {
    lines.push(
      '# 1. 安装面板 CA 根证书（用于验证服务器身份）',
      `$Ca = ${psq(pki.caDer().toString('base64'))}`,
      '[IO.File]::WriteAllBytes("$Tmp\\ca.cer", [Convert]::FromBase64String($Ca))',
      'Import-Certificate -FilePath "$Tmp\\ca.cer" -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null',
      '',
    );
  }
  if (certMode) {
    lines.push(
      '# 2. 导入用户证书',
      `$P12 = ${psq(p12.toString('base64'))}`,
      `$P12Pass = ConvertTo-SecureString ${psq(p12Password)} -AsPlainText -Force`,
      '[IO.File]::WriteAllBytes("$Tmp\\user.p12", [Convert]::FromBase64String($P12))',
      'Import-PfxCertificate -FilePath "$Tmp\\user.p12" -CertStoreLocation Cert:\\LocalMachine\\My -Password $P12Pass | Out-Null',
      '',
    );
  }
  lines.push(
    '# 3. 创建 VPN 连接（已存在则先删除）',
    'Get-VpnConnection -Name $Name -ErrorAction SilentlyContinue | ForEach-Object { Remove-VpnConnection -Name $Name -Force }',
    `Add-VpnConnection -Name $Name -ServerAddress $Server -TunnelType Ikev2 -EncryptionLevel Required -AuthenticationMethod ${certMode ? 'MachineCertificate' : 'Eap'} -SplitTunneling:$${c.full ? 'false' : 'true'} -RememberCredential -Force`,
    'Set-VpnConnectionIPsecConfiguration -ConnectionName $Name -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 -PfsGroup None -Force',
  );
  for (const r of c.routes) lines.push(`Add-VpnConnectionRoute -ConnectionName $Name -DestinationPrefix ${psq(r)}`);
  lines.push(
    '',
    'Remove-Item -Recurse -Force $Tmp',
    `Write-Host "完成！在 设置 → 网络和 Internet → VPN 中连接 “$Name”${certMode ? '' : `，用户名 ${user.username}`}" -ForegroundColor Green`,
    '',
  );
  // PowerShell 5.1 需要 BOM 才能正确识别 UTF-8 中文
  return Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(lines.join('\r\n'), 'utf8')]);
}

// ---------- Android strongSwan ----------
function sswan(state, user, { p12 } = {}) {
  const c = ctx(state, user);
  const certMode = user.auth_type === 'cert';
  const profile = {
    uuid: crypto.randomUUID(),
    name: c.name,
    type: certMode ? 'ikev2-cert' : 'ikev2-eap',
    remote: { addr: c.host, id: c.host },
    local: certMode ? { p12: p12.toString('base64') } : { eap_id: user.username },
  };
  if (c.selfSigned) profile.remote.cert = pki.caDer().toString('base64');
  if (!c.full) profile['split-tunneling'] = { subnets: c.routes.join(' ') };
  return JSON.stringify(profile, null, 2);
}

module.exports = { mobileconfig, windowsScript, sswan };
