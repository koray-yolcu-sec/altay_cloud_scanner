"""
EC2 Network Güvenlik Kontrolleri
Security Group 0.0.0.0/0 kontrolleri
"""

import logging
from typing import List, Dict, Optional

from botocore.exceptions import ClientError

from . import BaseFinder


logger = logging.getLogger(__name__)


class NetworkFinder(BaseFinder):
    """EC2 network güvenlik kontrolleri (Security Groups)"""

    CHECKS = {
        "public_ingress": True,
    }

    # Yüksek riskli portlar (0.0.0.0/0'dan gelirse HIGH)
    HIGH_RISK_PORTS = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        9200: "Elasticsearch",
        27017: "MongoDB",
        5601: "Kibana",
        8080: "HTTP Alternate",
    }

    # Web portları (0.0.0.0/0'dan gelirse LOW/INFO)
    WEB_PORTS = {
        80: "HTTP",
        443: "HTTPS",
    }

    def run(self) -> List[Dict]:
        """Network taramasını çalıştır"""
        try:
            ec2_client = self.session_manager.get_client("ec2", region_name=self.region)
            
            # Tüm security group'ları getir
            security_groups = self._describe_security_groups(ec2_client)
            
            if not security_groups:
                logger.info(f"{self.region} bölgesinde security group bulunamadı")
                return self.findings
            
            logger.info(f"{len(security_groups)} security group taranıyor...")
            
            for sg in security_groups:
                self._check_security_group(ec2_client, sg)
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDenied":
                self.add_error(
                    "EC2 SG listeleme",
                    "EC2 describe_security_groups erişimi reddedildi"
                )
            else:
                self.add_error("EC2 Network genel", f"ClientError: {e}")
        except Exception as e:
            self.add_error("EC2 Network genel", f"Beklenmeyen hata: {e}")
        
        return self.findings

    def _describe_security_groups(self, ec2_client) -> List[Dict]:
        """Tüm security group'ları listele"""
        sgs = []
        try:
            for page in self.session_manager.paginate(
                ec2_client, "describe_security_groups"
            ):
                sgs.extend(page.get("SecurityGroups", []))
        except Exception as e:
            logger.error(f"Security group listeleme hatası: {e}")
        return sgs

    def _check_security_group(self, ec2_client, sg: Dict) -> None:
        """Tek security group için kontrolleri çalıştır"""
        sg_id = sg.get("GroupId", "")
        sg_name = sg.get("GroupName", "")
        sg_arn = f"arn:aws:ec2:{self.region}:{sg.get('OwnerId', '')}:security-group/{sg_id}"
        
        # Description kontrolü (NAT, ALB gibi özel durumlar)
        description = sg.get("Description", "").lower()
        is_default_sg = sg_name == "default"
        is_nat_sg = "nat" in description
        is_alb_sg = "elb" in description or "load balancer" in description
        
        # Ingress rule'ları kontrol et
        if self.CHECKS["public_ingress"]:
            self._check_public_ingress(
                sg_id, sg_name, sg_arn, sg, is_default_sg, is_nat_sg, is_alb_sg
            )

    def _check_public_ingress(
        self,
        sg_id: str,
        sg_name: str,
        sg_arn: str,
        sg: Dict,
        is_default_sg: bool,
        is_nat_sg: bool,
        is_alb_sg: bool,
    ) -> None:
        """0.0.0.0/0 inbound rule kontrolü"""
        ingress_rules = sg.get("IpPermissions", [])
        
        for rule in ingress_rules:
            ip_ranges = rule.get("IpRanges", [])
            
            for ip_range in ip_ranges:
                cidr = ip_range.get("CidrIp", "")
                
                # 0.0.0.0/0 kontrolü
                if cidr == "0.0.0.0/0":
                    # Port'ları çıkar
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    ip_protocol = rule.get("IpProtocol")
                    
                    # Protocol: -1 = all traffic
                    if ip_protocol == "-1":
                        self._add_public_ingress_finding(
                            sg_id, sg_name, sg_arn, "ALL TRAFFIC", "ALL", is_default_sg, is_nat_sg, is_alb_sg
                        )
                        continue
                    
                    # Port aralığı veya tek port
                    ports = []
                    if from_port is not None and to_port is not None:
                        if from_port == to_port:
                            ports = [from_port]
                        else:
                            ports = list(range(from_port, to_port + 1))
                    
                    # Her port için kontrol
                    for port in ports:
                        self._check_public_port(
                            sg_id, sg_name, sg_arn, port, ip_protocol,
                            is_default_sg, is_nat_sg, is_alb_sg
                        )
            
            # IPv6 kontrolü (::/0)
            ipv6_ranges = rule.get("Ipv6Ranges", [])
            for ipv6_range in ipv6_ranges:
                cidr = ipv6_range.get("CidrIpv6", "")
                if cidr == "::/0":
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")
                    ip_protocol = rule.get("IpProtocol")
                    
                    if ip_protocol == "-1":
                        self._add_public_ingress_finding(
                            sg_id, sg_name, sg_arn, "ALL TRAFFIC (IPv6)", "ALL", is_default_sg, is_nat_sg, is_alb_sg
                        )
                    elif from_port is not None:
                        self._check_public_port(
                            sg_id, sg_name, sg_arn, from_port, ip_protocol,
                            is_default_sg, is_nat_sg, is_alb_sg, is_ipv6=True
                        )

    def _check_public_port(
        self,
        sg_id: str,
        sg_name: str,
        sg_arn: str,
        port: int,
        ip_protocol: str,
        is_default_sg: bool,
        is_nat_sg: bool,
        is_alb_sg: bool,
        is_ipv6: bool = False,
    ) -> None:
        """0.0.0.0/0'dan gelen port bazlı bulgu oluştur"""
        
        # NAT ve ALB için bazi exception'lar olabilir
        if is_nat_sg and port in [80, 443, 1024, 65535]:
            return  # NAT için normal
        
        if is_alb_sg and port in [80, 443]:
            return  # ALB için normal
        
        # Default SG için daha düşük severity
        severity_modifier = "" if not is_default_sg else " (Default SG)"
        
        # HIGH risk portları
        if port in self.HIGH_RISK_PORTS:
            port_name = self.HIGH_RISK_PORTS[port]
            
            self.add_finding(
                finding_id="AWS-EC2-PUBLIC-001",
                title=f"EC2 Security Group 0.0.0.0/0: {port_name} (Port {port}){severity_modifier}",
                severity="high",
                confidence="high",
                service="ec2",
                resource_arn=sg_arn,
                resource_name=sg_name,
                evidence=[
                    f"Port: {port} ({port_name})",
                    f"Protocol: {ip_protocol}",
                    f"Kaynak: 0.0.0.0/0" + (" (IPv6: ::/0)" if is_ipv6 else ""),
                ],
                risk=(
                    f"Security group port {port} ({port_name}) için dünyaya açık (0.0.0.0/0). "
                    "Bu durum unauthorized erişim ve brute-force saldırı riski oluşturur."
                ),
                recommendation=[
                    f"Port {port} için 0.0.0.0/0 kullanmaktan kaçının",
                    "Spesifik IP aralıkları veya güvenilir kaynaklar kullanın",
                    "AWS Security Groups best practice'lerini inceleyin",
                    "Security Group referansları kullanın"
                ],
                score_impact=-12,
                tags=["ec2", "security-group", "public-access", "network"],
            )
        
        # Web portları
        elif port in self.WEB_PORTS:
            port_name = self.WEB_PORTS[port]
            
            # Default SG ve web portları için LOW severity
            if is_default_sg:
                severity = "low"
                score = -3
            else:
                severity = "low"
                score = -3
            
            self.add_finding(
                finding_id="AWS-EC2-PUBLIC-002",
                title=f"EC2 Security Group 0.0.0.0/0: {port_name} (Port {port}){severity_modifier}",
                severity=severity,
                confidence="medium",
                service="ec2",
                resource_arn=sg_arn,
                resource_name=sg_name,
                evidence=[
                    f"Port: {port} ({port_name})",
                    f"Protocol: {ip_protocol}",
                    f"Kaynak: 0.0.0.0/0" + (" (IPv6: ::/0)" if is_ipv6 else ""),
                ],
                risk=(
                    f"Security group web port {port} ({port_name}) için dünyaya açık. "
                    "Bu durum web servisi için normal olabilir ancak dikkatli olunmalıdır."
                ),
                recommendation=[
                    f"Port {port} için gerçekten 0.0.0.0/0 gerekiyor mu kontrol edin",
                    "Web servisi ise WAF kullanmayı düşünün",
                    "Rate limiting ve monitoring yapın"
                ],
                score_impact=score,
                tags=["ec2", "security-group", "web", "network"],
            )
        
        # Diğer portlar
        else:
            self.add_finding(
                finding_id="AWS-EC2-PUBLIC-003",
                title=f"EC2 Security Group 0.0.0.0/0: Port {port}{severity_modifier}",
                severity="medium",
                confidence="medium",
                service="ec2",
                resource_arn=sg_arn,
                resource_name=sg_name,
                evidence=[
                    f"Port: {port}",
                    f"Protocol: {ip_protocol}",
                    f"Kaynak: 0.0.0.0/0" + (" (IPv6: ::/0)" if is_ipv6 else ""),
                ],
                risk=(
                    f"Security group port {port} için dünyaya açık. "
                    "Bu port neden açık olduğunu gözden geçirin."
                ),
                recommendation=[
                    f"Port {port} için gerekli IP aralıkları kısıtlayın",
                    "Security Group kurallarını düzenli olarak gözden geçirin",
                    "Kullanılmayan portları kapatın"
                ],
                score_impact=-5,
                tags=["ec2", "security-group", "network"],
            )

    def _add_public_ingress_finding(
        self,
        sg_id: str,
        sg_name: str,
        sg_arn: str,
        traffic_desc: str,
        protocol: str,
        is_default_sg: bool,
        is_nat_sg: bool,
        is_alb_sg: bool,
    ) -> None:
        """ALL TRAFFIC bulgu ekleyici"""
        severity = "high" if not is_default_sg else "medium"
        
        self.add_finding(
            finding_id="AWS-EC2-PUBLIC-004",
            title=f"EC2 Security Group 0.0.0.0/0: {traffic_desc}",
            severity=severity,
            confidence="high",
            service="ec2",
            resource_arn=sg_arn,
            resource_name=sg_name,
            evidence=[
                f"Traffic: {traffic_desc}",
                f"Protocol: {protocol}",
                "Kaynak: 0.0.0.0/0",
            ],
            risk=(
                f"Security group tüm traffic için dünyaya açık (0.0.0.0/0). "
                "Bu durum çok yüksek güvenlik riski oluşturur."
            ),
            recommendation=[
                "All traffic rule'ını kaldırın",
                "Gereken spesifik portları tanımlayın",
                "IP kısıtlaması ekleyin",
                "Minimum privilege prensibini uygulayın"
            ],
            score_impact=-20,
            tags=["ec2", "security-group", "public-access", "network"],
        )