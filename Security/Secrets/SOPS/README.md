# Azure: Cifrado de secretos con SOPS

## Description

- Un saludo, espero se encuentre bien
- A continuación detallaremos, desde Infraestructura Digicem - CyberSecurity, la guía del paso a paso para:
- Cifrar Secretos de repositorios o estructuras de archivos en  repos desde una llave

## Requerimientos

- Tener una  suscripción.
- Tener un equipo local donde administrar cambios de repositorios y subirlos hacia  los repositorios en  DevOps, sobre Repos.
- Contar con el archivo, repositorio o estructura a cifrar en AES256, bajo un formato JSON.

## Guía

- Herramienta de almacenamiento de secretos dentro del  portal.
- Herramienta de gestión de recursos en la nube, a nivel de IaaS, PaaS, SaaS.
- Repos: Herramienta de gestión de pipelines en pasos por el branching strategy declarado de git-flow y trunk, entre los entornos: Dev, STA y Prod, algunos HotFixes y Features de recuperación de aplicaciones comprometidas.

## Etapas

### Publicaciones

- Por favor, puedes hacer uso de la siguientes estructuras como bases para lograr el fin solicitado.

### deb_install.sh

~~~ BASH
#!/usr/bin/env bash

#######################################################################################################################
# This script does three fundamental things:                                                                          #
#   1. Add Microsoft's GPG Key has a trusted source of apt packages.                                                  #
#   2. Add Microsoft's repositories as a source for apt packages.                                                     #
#   3. Installs the Azure CLI from those repositories.                                                                #
# Given the nature of this script, it must be executed with elevated privileges, i.e. with `sudo`.                    #
#                                                                                                                     #
# Remember, with great power comes great responsibility.                                                              #
#                                                                                                                     #
# Do not be in the habit of executing scripts from the internet with root-level access to your machine. Only trust    #
# well-known publishers.                                                                                              #
#######################################################################################################################

set -e

if [[ $# -ge 1 && $1 == "-y" ]]; then
    global_consent=0
else
    global_consent=1
fi

function assert_consent {
    if [[ $2 -eq 0 ]]; then
        return 0
    fi

    echo -n "$1 [Y/n] "
    read consent
    if [[ ! "${consent}" == "y" && ! "${consent}" == "Y" && ! "${consent}" == "" ]]; then
        echo "'${consent}'"
        exit 1
    fi
}

global_consent=0 # Artificially giving global consent after review-feedback. Remove this line to enable interactive mode

setup() {

    assert_consent "Add packages necessary to modify your apt-package sources?" ${global_consent}
    set -v
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y apt-transport-https lsb-release gnupg curl
    set +v

    assert_consent "Add Microsoft as a trusted package signer?" ${global_consent}
    set -v
    curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /etc/apt/trusted.gpg.d/microsoft.gpg
    set +v

    assert_consent "Add the Azure CLI Repository to your apt sources?" ${global_consent}
    set -v
    # Use env var DIST_CODE for the package dist name if provided
    if [[ -z $DIST_CODE ]]; then
        CLI_REPO=$(lsb_release -cs)
        shopt -s nocasematch
        ERROR_MSG="Unable to find a package for your system. Please check if an existing package in https://packages.microsoft.com/repos/azure-cli/dists/ can be used in your system and install with the dist name: 'curl -sL https://aka.ms/InstallAzureCLIDeb | sudo DIST_CODE=<dist_code_name> bash'"
        if [[ ! $(curl -sL https://packages.microsoft.com/repos/azure-cli/dists/) =~ $CLI_REPO ]]; then
            DIST=$(lsb_release -is)
            if [[ $DIST =~ "Ubuntu" ]]; then
                CLI_REPO="jammy"
            elif [[ $DIST =~ "Debian" ]]; then
                CLI_REPO="bullseye"
            elif [[ $DIST =~ "LinuxMint" ]]; then
                CLI_REPO=$(cat /etc/os-release | grep -Po 'UBUNTU_CODENAME=\K.*') || true
                if [[ -z $CLI_REPO ]]; then
                    echo $ERROR_MSG
                    exit 1
                fi
            else
                echo $ERROR_MSG
                exit 1
            fi
        fi
    else
        CLI_REPO=$DIST_CODE
        if [[ ! $(curl -sL https://packages.microsoft.com/repos/azure-cli/dists/) =~ $CLI_REPO ]]; then
            echo "Unable to find an azure-cli package with DIST_CODE=$CLI_REPO in https://packages.microsoft.com/repos/azure-cli/dists/."
            exit 1
        fi
    fi
    echo "deb [arch=$(dpkg --print-architecture)] https://packages.microsoft.com/repos/azure-cli/ ${CLI_REPO} main" \
        > /etc/apt/sources.list.d/azure-cli.list
    apt-get update
    set +v

    assert_consent "Install the Azure CLI?" ${global_consent}
    apt-get install -y azure-cli

}

setup  # ensure the whole file is downloaded before executing
~~~

#### .sops.yaml

~~~ BASH
creation_rules:
  - azure_keyvault: https://dev-kv-devops-compañia.vault.azure.net/keys/sops-key/L1av3DeC1fr4d0
~~~

#### dockerfile

~~~ GO
FROM ubuntu

ADD . .

USER root

# MANDATORY UPDATE.
RUN apt update -y; \
apt install curl -y; \
dpkg -i sops_3.7.3_amd64.deb; \
curl -sL https://aka.ms/InstallAzureCLIDeb | bash;
~~~

#### env.json

~~~ JSON
{
    "Logging": {
            "LogLevel": {
                    "Default": "ENC[AES256_GCM,data:pcoxU6/mRmhi4CY=,iv:W1urE1wsbICW25DKYjHD64OcoRKzhevvCKeZnVMGBK8=,tag:Gst537NfKyyRIWT3jiBzDA==,type:str]",
                    "Microsoft.AspNetCore": "ENC[AES256_GCM,data:V5WOdx18dw==,iv:sAHY8IhKz4UO5MCYT2a3fQgh4+x7zLQ3oWqy4tGJyzE=,tag:DPI5eN8EVxRONTFOWakcow==,type:str]"
            }
    },
    "AllowedHosts": "ENC[AES256_GCM,data:Pg==,iv:Itp5F1KaRSqqzCbjQPzU2iRISOvHOxZ7KUsIvhGwcuE=,tag:WaiLpHsL/xCg9x4jKkGxTg==,type:str]",
    "QuickCommApi": {
            "AuthorityBaseUrl": "ENC[AES256_GCM,data:YU4j+OV6elr7RQxQtm98RWutdOph4TjgsGIqZPYKqdfa4OVNJHPgVpCoIURo/sEjdg/F,iv:/hGymZTVxIx5f/JIw1Hn/4R41b+F+QRKWrpenGQCM4I=,tag:P0o3VqUsvn7tk236L4Tniw==,type:str]",
            "BaseUrl": "ENC[AES256_GCM,data:EjDs36lX5RHRCisXYyBg9SMzie8CMp7NmGOKNbIvmHHEjBukCJYZEw==,iv:a8RXI6VRVwG+K+3le+nwTmvGlhgeTPctjEHGF6yXblg=,tag:ugdBjq5dsvsnFDg5OsUcwA==,type:str]",
            "ClientId": "ENC[AES256_GCM,data:0PBf2e8mPp9lgxmI/OD9HUXZ8SDSP3Y30i/B1Qi6QwnM7G+7,iv:pxFHuLWc5Ksf3bBPqCdK5ll5lxM1vSgtYKNUY0Etuk4=,tag:wjQ3NNiIXRIUDu0hJ76MlQ==,type:str]",
            "ClientSecret": "ENC[AES256_GCM,data:2CzXguqTXVQDDAbnjEOTGKMKGva4n5pqaPJXPeReJvMlpP29Wr35EcAhgeg=,iv:wMk5GLbLrUM5rfZm+jcVl9setqgpmGky7SfGIJWFMgg=,tag:8Slwvv16ncyKUKzwxPwPPA==,type:str]",
            "OrganizationId": "ENC[AES256_GCM,data:PdwIcWFLBL2sus8NdEwI8AAO+VmcGkqfBpCZ1vLopvWBfRmE,iv:Ww2dArWKY4cv1z2ffHmA78CMZd/kORQPoKPQWSyBC5U=,tag:ErAJ+gxAlGdJ36Ws3+zOLw==,type:str]",
            "SellerId": "ENC[AES256_GCM,data:0w7cCUWS0sNU3CneFthqF0q7CUVp32uEifQogXIaxjYtCtmf,iv:kw4yd6rPqRNAYOQoemUEG9Zx25Es2HjvTx8m5J1R7Tc=,tag:ZkqZRBZsO3oKe3YElHi3iw==,type:str]",
            "LoginClientId": "ENC[AES256_GCM,data:u/kqNATWniIxYT0Tqr9Q/aQtBYaHfZO36JofL0gowms65hcc,iv:NAJRT9Lid0WLC85tfSoFNY2qryvD1AQLdTzoIy2jOOo=,tag:5OCPWphMwk33oTZe+F2+eg==,type:str]",
            "LoginClientSecret": "ENC[AES256_GCM,data:Ii/dm4lvQiNfizxJk6q+qQJjc3SBApj4UuFHu1pJe9fOv+2c9zQAE4+Kbms=,iv:I3ppsz0ZclHpFj3JkRLMU6ktfk+OzSuyGvChYazuJPw=,tag:e+ODbcTjd9D2uAB2PTDevw==,type:str]"
    },
    "ShippingExperienceApi": {
            "BaseUrl": "ENC[AES256_GCM,data:sDe97hMZN3eOWrNsV1eHmuwXskez3qYXOmdGVAM5g8u0VkSsJZMek3oCBP8aXCTa0gFz5urr26uqhLU=,iv:tVyDwcWn4gzTAPih5uEoPu6jW4c9gNJ+CzqiPP87CTE=,tag:6a8N8tv2gz6K31VB8RoqAA==,type:str]",
            "CreateShippingExperienceFunctionKey": "ENC[AES256_GCM,data:oKIlMbVqCsHX/1j79EIIcTa8rItbl7U3d8dlzqj13h1mAWYLmx/233BKWBTr/1AnuKFnocLH3aM=,iv:W2Sm/vxozdJprYpOQf22JA4wiwkpWlTraRWuhU0j068=,tag:fBvRCVKX3k7nCUtkFYhaQw==,type:str]",
            "GetShippingExperienceScoreOptionsFunctionKey": "ENC[AES256_GCM,data:rUSPoR6lNUAe8VjZddJTkqLoIkRulA9u0R7w6Rfo0dn2A88twAOTnvG783aqL/qv92uK8EUm/14=,iv:W8srR+SrwhiFApoxJ60qkRaVEAuXjKsjiQIbZmWpCpA=,tag:aO126TuUQ8Txb5XoeIw4Wg==,type:str]",
            "GetShippingExperienceByClientRucFunctionKey": "ENC[AES256_GCM,data:aZ+WT33KSiuDw6Xxe3C14mPMxvdTSYenKZJO64ObysRt0DqT3+AuxUtwPqpn7K+CRMEVzPLVa64=,iv:+T9frU01x4bRI0bI9sFTrado+YzERPo4Rgd+HTzNnJI=,tag:E+/vNzQq+BxFkL1olZlerw==,type:str]"
    },
    "ShippingDatesApi": {
            "BaseUrl": "ENC[AES256_GCM,data:NxKPIZoPDZQY/gpewIrbbhkufqbLUi5FOuZV84fL0nhXEFkN/yH+IxqFVhRTtzgcxxmFuU0N,iv:Xt8Dpa/7F/1vGpzE0Csfdi0qRQfwrPvadKUkSEPy1dA=,tag:YT23wN2ZH/a+EYKVGeEnNQ==,type:str]",
            "GetAvailableShippingDatesFunctionKey": "ENC[AES256_GCM,data:6NzRsqMrGqr/J3/G95uHo25ZPCzj+DlFwbTKTs1UPl5i3YHzKDT3q4TJTk27y83vtGN07YTnqyU=,iv:QsnXikSZXskSKnDXkFOGVPo2Vle3sb8ucufYRXfvzoI=,tag:NERg5zQ+htxDy0YhZ2mAgA==,type:str]",
            "SaveSaleOrderShippingFunctionKey": "ENC[AES256_GCM,data:yNGe6MIFONHUMj8ufPFVm27pAmpPPmX6M6ImEcEM42LXHdc3c2OCxtyvaGSOxs5Umqa011Puf9g=,iv:kny9Mm8qzQR/Rqjt2lc85Fb4D6WsRJDuAiJLHlke01s=,tag:VC1LyfKvxPIBkFKaxw66aw==,type:str]"
    },
    "TicketManagerApi": {
            "BaseUrl": "ENC[AES256_GCM,data:hW9j64c2u9MOs7q1hE+/1ZxhEy2kyCVkwB/m6tDSW/IMUgAUa7zcCLFl1ygHMMuwTgOMtZFA,iv:kpvhaNpN2llGBpWZXo9xIVMLwpUMgDv1YWoLXvbuUbY=,tag:NQ5273Itkll8MqZ3AetxbA==,type:str]"
    },
    "PaymentsApi": {
            "BaseUrl": "ENC[AES256_GCM,data:dMn/Ss5k9mTVGA9ZoEJB1pmnNx7hF/GvMT06vKdfz92WtFpN9+TyXYpmyvQDkFJI,iv:jwDnfc8rDQWZummMmMHbxEhZjLVrRMMlxC63ISjRzDw=,tag:EWq/fu6R5s34vR0OeEqHzw==,type:str]",
            "CreditSummaryFunctionKey": "ENC[AES256_GCM,data:ouUml1INYqZXpaXU6YcOKtl7FMwbWmbGqazLvrvX3tvRrJx/AxcntGwtKPmimShZoBma3JyrGbo=,iv:V0cyb3h76NP0fYNY02uJdkKHKlA4UyBv0f4FrNlAS6E=,tag:VqM1mPdBhC0QWseUE1JzGw==,type:str]",
            "ChargeFunctionKey": "ENC[AES256_GCM,data:WqrIhCPAS0w1GbPFOJMk3uBHY+ZkvFH4GU1mKpBEYJZDzWmd3m93DzR0j9x+9l1QY+QGURltYL0=,iv:4+D7v4Qn4BkmfuQ+3jyVc7Fko/1T0l9qzQqevRjg+gQ=,tag:ZU7lKCLDWeYBXlqkxzTWkw==,type:str]",
            "ReimburseFunctionKey": "ENC[AES256_GCM,data:VcVQgh5AoltIhuAGI62DavLblJfVpFHYIfP1TNjufPsK7ryhQxm3KIOW2lpKgcsZi77fL7Ky79Y=,iv:f8i7tSNYtExO/F3VMoZJ+DRTAnoWbQOqnqW9XvYksb4=,tag:eizA8mvkbe5QyV24ao5E1Q==,type:str]"
    },
    "LoyaltyApi": {
            "BaseUrl": "ENC[AES256_GCM,data:h9/aLDqrHdYsjjkNrt7d1zq78UZ0oDdkd2zcUouUcnSmwIUyPoC85t2Yhe0tHG19saUbfN+HD3M=,iv:SLYUHLHkT3ZCmoegleRrNkWYMO4gdT3DWNPcqMcsOLc=,tag:FwtPwbei7KYUfSYqzuPoGQ==,type:str]",
            "LoyaltyPointsSummaryByClientIdFunctionKey": "ENC[AES256_GCM,data:WFQddDxNk23YlX2sFSvLQYNuonOBfVw5qgWIQq6Wv7Dq830aNaoEV3cBex8ey8esay+/75D5gwc=,iv:4uzgLZzYMhanqkXKxSd/wOxYAS/9j4Igu0qpS+XGdes=,tag:DerKLOYaaeY3ZPMogyCeOQ==,type:str]",
            "LoyaltyPointsTransactionsByClientIdFunctionKey": "ENC[AES256_GCM,data:9vIqsCWC+dXrtnzEQgZnKlSX4BTH9+moWkSQzXqmLVp6DP66b0tRUHVyh1SPpNxEj4orveLa2H0=,iv:1qC9kk+Fy3kylCf7/7Zhco8pwJPKMi2U2O0baNHIKwM=,tag:H2d31WoLnMStN1GoQW7+VQ==,type:str]",
            "AddLoyaltyPointTransactionFunctionKey": "ENC[AES256_GCM,data:mBqfUJoA5CiyTOqVKPxFsTJ5NkyfWw78kF/org+Dpv5Z7yQxfq4VeesaaI6rpqrfC7yQUuY6WAY=,iv:akF+L2dtR1pDHaJ0fN2gWnUFKfUuDU+IMHqUIxwm8MY=,tag:2Ok0AnJEf7J/JxBUb4nPjQ==,type:str]"
    },
    "MarketingApi": {
            "BaseUrl": "ENC[AES256_GCM,data:sCQYyvQ9CVYkI4l5UzmpsdPqvhy56wll/I+3p64w+flc3dfuGn7OymBWMOzSf3VvXQ==,iv:ndrT1Q/p79IGLgqYWufj2zf3rZRbiD93uZwlf8aSheQ=,tag:/PYNos9whWMwSCc4iWh5fw==,type:str]",
            "GetTestimonialsFunctionKey": "ENC[AES256_GCM,data:rpYZZgpFpVLq8WnLgOvWSU8iFR7Bg53316b9ctA2ozJ4gMVT4RbBORiF69FG6b1D39iV9u8nUY4=,iv:K8byeHQzBjymsrb0POIWD1Fopl6axqJq9et56kkkgTs=,tag:AYOdHTN08UXPcplkOM7bbw==,type:str]",
            "GetNoveltiesFunctionKey": "ENC[AES256_GCM,data:GoDcuoBtJrO20rvKJiGy1Fm/JJc8UnRr9WX/nnV5g4zvMyRtx75JrdOFHxFuyKFTQVyqphd9q2w=,iv:fx9RpKgNfneeFxbiveX8kFwcXsB6x5Rq9X4PwMS3HlE=,tag:HaWmB7uKr/dA3wLSFHUNPw==,type:str]"
    },
    "NotificationsApi": {
            "BaseUrl": "ENC[AES256_GCM,data:BviIjbk9rlhE1QbaypQTPSmVP3hz2nhcg3Hs4m4FrVKJbQYy5uJMwb+6gyGdTQ+EY87dmg==,iv:meHaeQci6lSoTWHF7jvbrcKcSr/N9v1WPbcbMrnlxno=,tag:OozZjAlSjorb4PDyn4wJ9g==,type:str]",
            "SendOrderClaimEmailFunctionKey": "ENC[AES256_GCM,data:bj4fYNiZwNqpH/E4H0WYTwoR2gWiq0iyVOqfNnHIshMu/UIN5XFk71U0qo+FrRxRER3wUkO2Jbs=,iv:ofta4k9lovGO31qi9z02JzWs2BweOLrufvN843n3WV0=,tag:W90+e2caS+hp9lkDHkQy6g==,type:str]",
            "SendWelcomeClientCreatedEmailFunctionKey": "ENC[AES256_GCM,data:O6AVq3jlQWHQRvcoUIURh5sDq8hpo/VncG/MeQZgGLbQpxl3vu7pb0C2C+6ew9IVnZLsD7/m7GY=,iv:6ftX/gvo2DUH/vWIR8AxX1VoPxUVoBhTwdzdckeFoRI=,tag:6UXdR/KijiPCgTWIdMuA7w==,type:str]"
    },
    "ProductsApi": {
            "BaseUrl": "ENC[AES256_GCM,data:lYvm8wqOdXcca2NS/WPKQxhMP2fsretyerFWtL+ho8RxwpbFx4HqxdH9TXovkRapnx9UMKs9/GPorQ==,iv:qczwZnxuiMegyc6lebEsCy3DeCZ2kkf9XOhHq61ZAWY=,tag:UUxrdNp77m9IdpDxZu/FGw==,type:str]",
            "GetProductCategoriesFunctionKey": "ENC[AES256_GCM,data:q3VY+vvYyG5cnxP2Lhmclrngq2uZQkXEUc1vAbWGBVf/H48I2A9IkaRS+jq76vsOPCdUnLsz+Qg=,iv:0jNrmA/pH99wwcRAN/zHeCzGEB+hlKZVYUJYw7Tzz4c=,tag:MhmitaiXRJYQtX6TLPmueg==,type:str]",
            "GetWarehousesFunctionKey": "ENC[AES256_GCM,data:GJWFoXzj5G/zLqlxVtMsWSKqMb3kGwZN5FOCpb3V5zrLueLh1uOnYTkuo+1MPnQIDmePuL+D+vY=,iv:F9Bjx1zT5t9UdECHiagezTM922Snp6x5M2jabEgmo7A=,tag:RzArZ2kua1eUjlAQ06I6ig==,type:str]"
    },
    "BackOfficeApi": {
            "BaseUrl": "ENC[AES256_GCM,data:07M3JTQyVJaX/1N3zN0hifs+Pj0+4Q06SCYGE53dnOxPplSsvAT3t2I9nDNMkOcflUVRdnXPpSFJ5nKEoA==,iv:OPKxL+ge1BBLDSnVJuokuaVaMJGOwPedP5+A/pVDzBQ=,tag:6eVEycOZGB4kH3Z4MzsqJg==,type:str]",
            "CreateDistributorSaleOrderFunctionKey": "ENC[AES256_GCM,data:vKWGNcZ3JxvG03ncN/vXidcilfN1lQGm0H+cxYmwoXjlCWoCi6mRXQ70DQAXQ7MXpn/T8xb14Oo=,iv:6+XSk2cErJRRNhFXqg6KFV4y1cj38bWQNddCYP/Vjd4=,tag:u6x104Bdd4V8+4Up+K8FIQ==,type:str]"
    },
    "TMS": {
            "ProviderId": "ENC[AES256_GCM,data:GjWm81WtXHlgO7iyLylX0zfEA6ycmaxwB830LF+2vyDMg8fh,iv:z8V7efanX4+HT2DwO0rcvVVV7q43oR3PtJbVsMszXSA=,tag:t0tByIHxBiXCJHHifmb5Pw==,type:str]"
    },
    "SacContactInformation": {
            "Name": "ENC[AES256_GCM,data:jLKR0aq6a1v5BwGqLVaVhpbr9edOtTuI,iv:RgR9jZvunguiLPQmbm5WNXZNa9HuxAZfo1KJoHOAML8=,tag:zf3NFjcpRpKOtjz6xN5nnA==,type:str]",
            "Email": "ENC[AES256_GCM,data:00pZ8nCCoNGpiK5HxvGu9IHBa25iLQIiX6k=,iv:HqT72TF+M97O+L45TkITGdLi1PeO+q+85tjZc4gfsMc=,tag:GqW65FaxCyo0PoFyy3Dzrg==,type:str]",
            "PhoneNumber": "ENC[AES256_GCM,data:xTniukYqXlfsTEk=,iv:uMwxSR4NCl/Hf/65cZGiAfZ4tJD1rsqgcYVmqpxA6iI=,tag:oUoC7EKb9LNxApzcc6lccw==,type:str]"
    },
    "Cache": [
            {
                    "Name": "ENC[AES256_GCM,data:stBipS3udA==,iv:Mr8470TFYn0hpQOm7ZnhyybKxRzpJacbfD80fKWyOyM=,tag:0lsXADxGQx905M6fHfROtg==,type:str]",
                    "Hours": "ENC[AES256_GCM,data:Bw==,iv:PdlXAyeEr3vSQ36vG0PFrcuOAFHcgGRRqIxvE4/Yi+o=,tag:zOTp62n0fFDblGQxMgYTNQ==,type:str]",
                    "Minutes": "ENC[AES256_GCM,data:SQ==,iv:X/6lBr5p0ghVx46I4f6Zc7n43jz2yJMo7/J01xEoCgw=,tag:g11g0tgd87T2Moe8E033ng==,type:str]",
                    "seconds": "ENC[AES256_GCM,data:Xw==,iv:rV7fH4xyFfyzeRgfCJvAkrX2GOKAx1Rd2t37V74mbDs=,tag:c0iUDjYMlw/Y8ddcv4PbZw==,type:str]"
            },
            {
                    "Name": "ENC[AES256_GCM,data:zVq4jocJtVwh91Iq0R+3WB4ajAar9ZHT3g==,iv:HFenOuHXZyEqycLqt/O3Cy3NhOcgFOH8zq/MEatDjVY=,tag:uQJ6lQggBii2qRELoPs/pg==,type:str]",
                    "Hours": "ENC[AES256_GCM,data:nA==,iv:EzU5xp6SvBalSba5un/DFDcfFff4cFHv6ZwnihUx7ZI=,tag:h3kj7C24R+f2aXf8leRADg==,type:str]",
                    "Minutes": "ENC[AES256_GCM,data:Tg==,iv:DaQj+8LpQcDZb03S6eWwsVHgjK6SAL2MUYMaQTNh+TI=,tag:YXCQcHE8xk2CviBUBsyy1g==,type:str]",
                    "seconds": "ENC[AES256_GCM,data:Xg==,iv:gZs9AvkejOcNvIKc2pprc5MVz6/ZPunmO99eiLL4KHY=,tag:25l11MT6wM5P7mm3iI5GoQ==,type:str]"
            },
            {
                    "Name": "ENC[AES256_GCM,data:U+Iz1/OCa/OtxqZ9Bugn,iv:Znx3V5OMZne/2Dfg1Q//qCZ9ysV7QrSz1sr2FEVrx4M=,tag:GQ3eavdR4412tNmpZ6zStA==,type:str]",
                    "Hours": "ENC[AES256_GCM,data:qQ==,iv:qhjViy2GHvhPg2wz+KlZnXZWYuKTQHYp585NJmr8g1E=,tag:aHbqyK6VNCi2X2zPGrrYTQ==,type:str]",
                    "Minutes": "ENC[AES256_GCM,data:uQ==,iv:kHxpYLoEXW6++CTEEw0hmzj5tETH2EbJOqbdAzwr/lU=,tag:D6UoHiVQhftVphkDKV6nBw==,type:str]",
                    "seconds": "ENC[AES256_GCM,data:OQ==,iv:c4BprMkztShvBHPSMCHA943ssN+sICeLJ501rCJXlFk=,tag:WOrbbCWm48gOs3kM89nhSQ==,type:str]"
            },
            {
                    "Name": "ENC[AES256_GCM,data:oG7odeVSiwxTF1ka0g==,iv:qmU/50iScbKys6S2S55lS54G1M5r2XgaGvMHksHsWWE=,tag:+2E/qOT+HLRwt6osEvjmIw==,type:str]",
                    "Hours": "ENC[AES256_GCM,data:9yg4LQ==,iv:eyO8mEhTxajOQpgyKbnEiFR2Huz5GFM2qguxCsAcnsQ=,tag:05RuQbBjQXmoSLoA4qVnvA==,type:str]",
                    "Minutes": "ENC[AES256_GCM,data:zQ==,iv:Vv89UgIVmJWzmIVB0cHwIUQOGUpp00cNKNQoWBPmQQ8=,tag:RcdHVn44SILEKU1fuIP4lw==,type:str]",
                    "seconds": "ENC[AES256_GCM,data:0g==,iv:jTgd+JKbDwDpMT8L4kDe+MyrlqYhseM9I0BH8GzI3BI=,tag:A7IS0TsmzTaLjP+tYY5/Qw==,type:str]"
            },
            {
                    "Name": "ENC[AES256_GCM,data:nMGWH/6zZAoaamrj5UqHzOYf,iv:sNR5aS+JgXB2hXxduwqKTEubRWBO/3SSeAnc6jn+seA=,tag:vH9aE4e/t5tdPaunoGaiww==,type:str]",
                    "Hours": "ENC[AES256_GCM,data:zQY=,iv:/VmGbq0LsHqrbcWRhitNo5ZAsGePgZqRT2qE/Y4jzR4=,tag:gqNfoYf2K3EQ7SK/Nhs2Ow==,type:str]",
                    "Minutes": "ENC[AES256_GCM,data:Pw==,iv:rUpp3OKc2pT2TaEbIjZXOWyZvTjG7+oB+LRDPH24BD0=,tag:oEZMl2KniLEWUzJuBX6Xzg==,type:str]",
                    "seconds": "ENC[AES256_GCM,data:vQ==,iv:yZeV7HzZlIIJiMg6gdWM/V+LrCi9Rs6fdt1pt4lPnSs=,tag:CjuoY8xRINM1SrcyqqWKLA==,type:str]"
            },
            {
                    "Name": "ENC[AES256_GCM,data:uNcZ5tP/IXuPcwHD38KzfE32,iv:+rB4JnPW21tTdpEV7SalkSiXSJ1gHnSCAGx/RAMeE+w=,tag:FFgveZAi3C3PO6VIDuL0aQ==,type:str]",
                    "Hours": "ENC[AES256_GCM,data:BUo=,iv:Behwn5V3y6n7AjtYqFKMqdc9utSyDAtSjuR/bJ8YCbw=,tag:MT4iULSgLAmRw2XN0uA1gQ==,type:str]",
                    "Minutes": "ENC[AES256_GCM,data:Xg==,iv:1SO5fFqo7eQnKi+1HL8lldHzGEqsfieyXucy+uRTmKs=,tag:JJLz+SWBmqeZ6u9EMmyQMA==,type:str]",
                    "seconds": "ENC[AES256_GCM,data:+A==,iv:8XpAO41DZSYOqw7G6LF6HD0bqJUXsAOSJdx1tOlrUhI=,tag:+dtmxg8a/rUPAhcP3UTAeQ==,type:str]"
            },
            {
                    "Name": "ENC[AES256_GCM,data:cFGrDo8FnRjymPy8TJJW7aEGCQ==,iv:sn4cUNjmWcJd9ad3PcQFMNkOXeYDibG0ad+7D51Ha/E=,tag:eAIT9hAwnL0uhmbpqRGZRQ==,type:str]",
                    "Hours": "ENC[AES256_GCM,data:4v8=,iv:6m9L4Pf/I4jTuV4efvQRb7Y52M0VxCmmO2ZFfqxqQUM=,tag:Tr+CoVibbJJkRn+h+R4opw==,type:str]",
                    "Minutes": "ENC[AES256_GCM,data:JQ==,iv:xbARUEFm/J3v+8wWlyfNdH0WKmSwDIBSX/CZaBQLENs=,tag:dEmZYpfVb/k6hWfWieOyGA==,type:str]",
                    "seconds": "ENC[AES256_GCM,data:NA==,iv:9wWrbJA37LQMTFkCeV/pkCK+9YYF6u15VkMYicw7g9w=,tag:hAXhJU+MAJ4XLy7ips1+7g==,type:str]"
            }
    ],
    "sops": {
            "kms": null,
            "gcp_kms": null,
            "azure_kv": [
                    {
                            "vault_url": "https://dev-kv-devops-compañia.vault.azure.net",
                            "name": "sops-key",
                            "version": "L1av3DeC1fr4d0",
                            "created_at": "2023-04-04T02:38:51Z",
                            "enc": "S3cR3t0C1fr4d0"
                    }
            ],
            "hc_vault": null,
            "age": null,
            "lastmodified": "2023-04-04T02:38:53Z",
            "mac": "ENC[AES256_GCM,data:6QKv30pqpXKNymWbP+arhTMHfxx22HRiukbTQdTJB1clWaQC/KjUp+JX1NRl6mPnE0uIBiibwrRIu+1nzQrheGqcQuKN3WZvKzVQOU7B7tBtoaDnHQ999eliZArfONcgQrddAOEWNMwhpwdlSIexY8YBWkI+nKKLxljEZ3JIQ7g=,iv:Io3UfXg3jDh903u5O6RM8qCSsZhpaoNcM83y4plor3Y=,tag:ESxteAKnilRv9QPqJN3rhQ==,type:str]",
            "pgp": null,
            "unencrypted_suffix": "_unencrypted",
            "version": "3.7.3"
    }
}
~~~

### Construcción

- Por favor, puedes hacer uso de la siguiente sentencia para construir tu proyecto.

#### Comandos Docker

~~~ GO
docker build -t name-tag . --no-cache
~~~

- **docker:** API.
- **build:** Construir a imagen desde la API.
- **t:** Etiqueta para la imagen.
- **name-tag:** API.
- **.:** Ruta de despliegue.
- **--no-cache:** Elimina al final el cache de carga en construcción, para evitar podar ese recurso en memoria más tarde, via manual.

### Pruebas

- Por favor, puedes hacer uso de las siguientes sentencias para validar accesos a los recursos y la herramienta.

#### Comandos

~~~ BASH
az login
~~~

- **az:** API.
- **login:** Inicio de sesion sobre la plataforma , en una ventana aparte bajo un código de validación.

~~~ BASH
export AZURE_CLIENT_ID="AzUr3-C1eNt-1D"
~~~

- **export:** Declara la variable en sistemas operativos Unix igual Linux.
- **AZURE_CLIENT_ID:** Nombre de variable a setear.
- **=:** Operador lógico del valor de la variable.
- **"AzUr3-C1eNt-1D":** Valor de la variable a retornar, al ser llamada.

~~~ BASH
export AZURE_CLIENT_SECRET="AzUr3-C1eNt-5E(r3T";
~~~

- **;:** Operador de salto de sentencia en línea.

~~~ BASH
export AZURE_TENANT_ID="AzUr3-T3n4Nt-1D"
~~~

### Desplegar

- Por favor, puedes hacer uso de las siguientes sentencias para validar accesos a los recursos y la herramienta.

#### Comandos SOPS

~~~ BASH
sops -e env.json > env.enc.dev2; cat env.enc.dev2"
~~~

- **sops:** Herramienta de cifrado.
- **-e:** Parámetro o argumento de cifrar secretos.
- **env.json:** Archivo o estructura a cifrar.
- **>:** Redireccionamiento de salida según error, de la sentencia anterior.
- **env.enc.dev2:** Documento receptor de salida.
- **cat:** Concatena los valores desde consola sin requerir abrir un binario sobre el archivo.
