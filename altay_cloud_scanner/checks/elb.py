"""
ELB/ALB Güvenlik Kontrolleri
Internet-facing load balancer kontrolleri
"""

import logging
from typing import List, Dict, Optional

from botocore.exceptions import ClientError

from . import BaseFinder


logger = logging.getLogger(__name__)


class ELBFinder(BaseFinder):
    """ELB/ALB güvenlik kontrolleri"""

    CHECKS = {
        "internet_facing": True,
        "security_groups": True,
    }

    def run(self) -> List[Dict]:
        """ELB/ALB taramasını çalıştır"""
        try:
            # CLB (Classic Load Balancer)
            self._check_classic_load_balancers()
            
            # ALB/NLB (Application/Network Load Balancer)
            self._check_application_network_load_balancers()
            
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDenied":
                self.add_error(
                    "ELB listeleme",
                    "ELB describe_load_balancers erişimi reddedildi"
                )
            else:
                self.add_error("ELB genel", f"ClientError: {e}")
        except Exception as e:
            self.add_error("ELB genel", f"Beklenmeyen hata: {e}")
        
        return self.findings

    def _check_classic_load_balancers(self) -> None:
        """Classic Load Balancer'ları kontrol et"""
        try:
            elb_client = self.session_manager.get_client("elb", region_name=self.region)
            
            load_balancers = []
            for page in self.session_manager.paginate(
                elb_client, "describe_load_balancers"
            ):
                load_balancers.extend(page.get("LoadBalancerDescriptions", []))
            
            if not load_balancers:
                logger.info(f"{self.region} bölgesinde CLB bulunamadı")
                return
            
            logger.info(f"{len(load_balancers)} Classic Load Balancer taranıyor...")
            
            for lb in load_balancers:
                self._check_clb(lb)
            
        except Exception as e:
            logger.error(f"CLB kontrol hatası: {e}")

    def _check_application_network_load_balancers(self) -> None:
        """Application/Network Load Balancer'ları kontrol et"""
        try:
            elbv2_client = self.session_manager.get_client(
                "elbv2", region_name=self.region
            )
            
            load_balancers = []
            for page in self.session_manager.paginate(
                elbv2_client, "describe_load_balancers"
            ):
                load_balancers.extend(page.get("LoadBalancers", []))
            
            if not load_balancers:
                logger.info(f"{self.region} bölgesinde ALB/NLB bulunamadı")
                return
            
            logger.info(f"{len(load_balancers)} ALB/NLB taranıyor...")
            
            for lb in load_balancers:
                self._check_alb_nlb(elbv2_client, lb)
            
        except Exception as e:
            logger.error(f"ALB/NLB kontrol hatası: {e}")

    def _check_clb(self, lb: Dict) -> None:
        """Classic Load Balancer kontrolü"""
        lb_name = lb.get("LoadBalancerName", "")
        lb_dns = lb.get("DNSName", "")
        lb_arn = f"arn:aws:elasticloadbalancing:{self.region}:{lb.get('OwnerId', '')}:loadbalancer/{lb_name}"
        scheme = lb.get("Scheme", "")
        
        vpc_id = lb.get("VPCId", "")
        subnets = lb.get("Subnets", [])
        security_groups = lb.get("SecurityGroups", [])
        
        # Internet-facing kontrolü
        if self.CHECKS["internet_facing"] and scheme == "internet-facing":
            self._add_internet_facing_finding(
                lb_name, lb_arn, "Classic Load Balancer", vpc_id, security_groups
            )
        
        # Security Group kontrolü
        if self.CHECKS["security_groups"]:
            self._check_lb_security_groups(
                lb_name, lb_arn, "Classic Load Balancer", vpc_id, security_groups
            )

    def _check_alb_nlb(self, elbv2_client, lb: Dict) -> None:
        """Application/Network Load Balancer kontrolü"""
        lb_arn = lb.get("LoadBalancerArn", "")
        lb_name = lb.get("LoadBalancerName", "")
        lb_dns = lb.get("DNSName", "")
        lb_type = lb.get("Type", "")  # application, network, gateway
        scheme = lb.get("Scheme", "")
        
        vpc_id = lb.get("VpcId", "")
        security_groups = lb.get("SecurityGroups", [])
        
        # Internet-facing kontrolü
        if self.CHECKS["internet_facing"] and scheme == "internet-facing":
            self._add_internet_facing_finding(
                lb_name, lb_arn, f"{lb_type.capitalize()} Load Balancer", vpc_id, security_groups
            )
        
        # Security Group kontrolü (Network LB'de SG yok)
        if self.CHECKS["security_groups"] and lb_type in ["application"]:
            self._check_lb_security_groups(
                lb_name, lb_arn, f"{lb_type.capitalize()} Load Balancer", vpc_id, security_groups
            )

    def _add_internet_facing_finding(
        self,
        lb_name: str,
        lb_arn: str,
        lb_type: str,
        vpc_id: str,
        security_groups: List[str],
    ) -> None:
        """Internet-facing bulgu ekle"""
        sg_str = ", ".join(security_groups[:3])  # İlk 3 SG
        
        self.add_finding(
            finding_id="AWS-ELB-PUBLIC-001",
            title=f"Load Balancer Internet-Facing ({lb_type})",
            severity="medium",
            confidence="high",
            service="elb",
            resource_arn=lb_arn,
            resource_name=lb_name,
            evidence=[
                f"Type: {lb_type}",
                f"Scheme: internet-facing",
                f"VPC: {vpc_id}",
                f"Security Groups: {sg_str} ({len(security_groups)} adet)"
            ],
            risk=(
                f"{lb_type} internet-facing olarak yapılandırılmış. "
                "Bu durum load balancer'ın internetten erişilebilir olması demektir. "
                "Web servisi için normal olabilir ancak dikkatli olunmalıdır."
            ),
            recommendation=[
                "Gerçekten internet-facing olup olmadığını doğrulayın",
                "Eğer gerekmiyorsa internal olarak değiştirin",
                "WAF kullanmayı düşünün",
                "Security Group kurallarını kısıtlayın",
                "SSL/TLS sertifikası kullanın"
            ],
            score_impact=-5,
            tags=["elb", "public-access", "load-balancer"],
        )

    def _check_lb_security_groups(
        self,
        lb_name: str,
        lb_arn: str,
        lb_type: str,
        vpc_id: str,
        security_groups: List[str],
    ) -> None:
        """Load balancer security group'larını kontrol et"""
        if not security_groups:
            return
        
        try:
            # Security group detaylarını getir
            ec2_client = self.session_manager.get_client("ec2", region_name=self.region)
            
            sg_details = ec2_client.describe_security_groups(
                GroupIds=security_groups
            ).get("SecurityGroups", [])
            
            # Her SG için 0.0.0.0/0 kontrolü
            for sg in sg_details:
                sg_id = sg.get("GroupId", "")
                sg_name = sg.get("GroupName", "")
                
                # Ingress rule'ları kontrol et
                ingress_rules = sg.get("IpPermissions", [])
                
                for rule in ingress_rules:
                    ip_ranges = rule.get("IpRanges", [])
                    
                    for ip_range in ip_ranges:
                        cidr = ip_range.get("CidrIp", "")
                        
                        # 0.0.0.0/0 kontrolü
                        if cidr == "0.0.0.0/0":
                            from_port = rule.get("FromPort")
                            to_port = rule.get("ToPort")
                            ip_protocol = rule.get("IpProtocol")
                            
                            # Port bilgisi
                            port_str = "ALL"
                            if from_port is not None:
                                if from_port == to_port:
                                    port_str = str(from_port)
                                else:
                                    port_str = f"{from_port}-{to_port}"
                            
                            self.add_finding(
                                finding_id="AWS-ELB-SG-PUBLIC-001",
                                title=f"Load Balancer SG 0.0.0.0/0: Port {port_str}",
                                severity="medium",
                                confidence="high",
                                service="elb",
                                resource_arn=lb_arn,
                                resource_name=lb_name,
                                evidence=[
                                    f"Load Balancer: {lb_name}",
                                    f"Security Group: {sg_name} ({sg_id})",
                                    f"Port: {port_str}",
                                    f"Protocol: {ip_protocol}",
                                    "Kaynak: 0.0.0.0/0"
                                ],
                                risk=(
                                    f"Load balancer bağlı security group port {port_str} "
                                    "için dünyaya açık. Bu durum unauthorized erişim riski oluşturabilir."
                                ),
                                recommendation=[
                                    f"Port {port_str} için 0.0.0.0/0 kullanmaktan kaçının",
                                    "Spesifik IP aralıkları kullanın",
                                    "Security Group kurallarını gözden geçirin",
                                    "WAF ve rate limiting kullanmayı düşünün"
                                ],
                                score_impact=-8,
                                tags=["elb", "security-group", "public-access", "load-balancer"],
                            )
            
        except Exception as e:
            logger.warning(f"ELB SG kontrol hatası ({lb_name}): {e}")