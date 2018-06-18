#!/usr/bin/python
# ####################################################################################################
#
#      @Author: Marcos Vasconcelos
#      @email: marvinred@gmail.com
#      @Version: 1.0
#      @Date: 06/18/2018
#      @Description: Script for statistics collection in JBoss Fuse environment
#
#
# ####################################################################################################
# ####################################################################################################
# ####################################################################################################

import ConfigParser
import base64
import csv
import getopt
import glob
import os
import socket
import sys
import time
import getpass

from pyjolokia import Jolokia

# #### Format date
formatDate = "%d-%b-%Y:%H:%M:%S %Z"
timestamp = time.strftime(formatDate)

# ### Config file
config = ConfigParser.RawConfigParser()
config.read('/app/scripts/fuse-stats/conf/ConfigFile.properties')


# ######################
# Function memoryUsageStatus -- Execute Memory used as percentage and
# verify average according memoryTestTotal number
# ###################################################################
def memoryUsageStatus():
    # type: () -> object
    serverAddress = config.get('RootContainerSection', 'serverAddress')
    rootContainer = config.get('RootContainerSection', 'rootContainer')
    appContainers = config.get('AppContainerSection', 'appContainers')
    gatewayContainers = config.get('GatewayContainerSection', 'gatewayContainer')
    jlkUserName = config.get('RootContainerSection', 'jlkUserName')
    jlkUserPassword = config.get('RootContainerSection', 'jlkUserPassword')
    memoryTestTotal = config.get('RootContainerSection', 'memoryTestTotal')
    arrayContainersInstances = []
    arrayContainersInstances.append(rootContainer)
    arrayContainersInstances.append(gatewayContainers)
    arrayContainersInstances.extend(appContainers.split(','))

    for contSplit in arrayContainersInstances:

        if 'root' in contSplit:
            # Setting adminPort
            admPort = config.get('RootContainerSection', contSplit + '_adm_port')
        elif 'SIL' in contSplit:
            admPort = config.get('AppContainerSection', contSplit + '_adm_port')
        elif 'gateway' in contSplit:
            admPort = config.get('GatewayContainerSection', contSplit + '_adm_port')

        # Checking if adminPort is ok to execute test if not ok the test will be interrupted
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        result = sock.connect_ex((serverAddress, int(admPort)))

        # Looping to validate each admin port set in ConfigFile.properties
        if result == 0:

            # ###############################################
            # ## Jolokia URL is based in serverAddress in ConfigFile.properties RootContainerSection
            j4p = Jolokia('http://' + serverAddress + ':' + admPort + '/jolokia/')

            # # Using Jolokia Authentication
            j4p.auth(httpusername=decode(jlkUserName), httppassword=decode(jlkUserPassword))

            # Request memory attributes
            memory = j4p.request(type='read', mbean='java.lang:type=Memory', attribute='HeapMemoryUsage')
            maxMemory = memory['value']['max']
            usedMemory = memory['value']['used']
            # Transform memory used in percentage of Max memory (Xmx)
            memoryUsedPercentage = (usedMemory * 100) / maxMemory

            fmemoControl = '/app/scripts/fuse-stats/control/.' + contSplit + '.txt'

            if len((glob.glob(fmemoControl))) == 0:
                with open(fmemoControl, 'wb') as csvfile:
                    csvWriter = csv.writer(csvfile)
                    csvWriter.writerow([str(memoryUsedPercentage), ])
                with open(fmemoControl, 'rb') as csvfile:
                    csvReader = csv.reader(csvfile)
                    calcMemAvg = 0
                    coutMemTest = 0
                    for rowMemValue in csvReader:
                        calcMemAvg = calcMemAvg + int(rowMemValue[0])
                        coutMemTest = coutMemTest + 1
                memAvg = calcMemAvg / coutMemTest
                print contSplit + ' ' + str(memAvg)
            elif len((glob.glob(fmemoControl))) == 1:
                with open(fmemoControl, 'a') as csvfile:
                    csvWriter = csv.writer(csvfile)
                    csvWriter.writerow([str(memoryUsedPercentage), ])
                    teste = 0
                with open(fmemoControl, 'rb') as csvfile:
                    csvReader = csv.reader(csvfile)
                    calcMemAvg = 0
                    countMemTest = 0

                    for rowMemValue in csvReader:
                        calcMemAvg = calcMemAvg + int(rowMemValue[0])
                        countMemTest = countMemTest + 1

                if countMemTest >= int(memoryTestTotal):
                    os.remove(str(fmemoControl))

                memAvg = calcMemAvg / coutMemTest
                print contSplit + ' ' + str(memAvg)

        else:
            print contSplit + ' 0'


# ######################
# Function portValidate -- Execute admin validation in Fuse containers
# ###################################################################
def portValidate():
    # type: () -> object
    serverAddress = config.get('RootContainerSection', 'serverAddress')
    rootContainer = config.get('RootContainerSection', 'rootContainer')
    appContainers = config.get('AppContainerSection', 'appContainers')
    gatewayContainers = config.get('GatewayContainerSection', 'gatewayContainer')

    # Extend Containers array
    arrayContainersInstances = []
    arrayContainersInstances.append(rootContainer)
    arrayContainersInstances.append(gatewayContainers)
    arrayContainersInstances.extend(appContainers.split(','))

    # Looping to validate each admin port set in ConfigFile.properties
    for contSplit in arrayContainersInstances:
        if 'root' in contSplit:
            # adminPort.append(config.get('RootContainerSection', contSplit+'_adm_port'))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            result = sock.connect_ex(
                (serverAddress, int(config.get('RootContainerSection', contSplit + '_adm_port'))))
            if result == 0:
                print contSplit + ' ' + str(result)
            else:
                print contSplit + ' ' + str(result)
        elif 'SIL' in contSplit:
            # adminPort.extend(config.get('AppContainerSection', contSplit + '_adm_port'))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            result = sock.connect_ex(
                (serverAddress, int(config.get('AppContainerSection', contSplit + '_adm_port'))))
            if result == 0:
                print contSplit + ' ' + str(result)
            else:
                print contSplit + ' ' + str(result)
        elif 'gw' in contSplit:
            # adminPort.extend(config.get('AppContainerSection', contSplit + '_adm_port'))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            result = sock.connect_ex(
                (serverAddress, int(config.get('GatewayContainerSection', contSplit + '_adm_port'))))
            if result == 0:
                print contSplit + ' ' + str(result)
            else:
                print contSplit + ' ' + str(result)


# ######################
# Function appPortValidate -- Execute admin validation in Fuse containers
# #################################################################33
def appPortValidate():
    serverAddress = config.get('RootContainerSection', 'serverAddress')
    appContainers = config.get('AppContainerSection', 'appContainers')
    gatewayContainers = config.get('GatewayContainerSection', 'gatewayContainer')

    # Extend Containers array
    arrayContainersInstances = []
    arrayContainersInstances.append(gatewayContainers)
    arrayContainersInstances.extend(appContainers.split(','))

    # Looping to validate each app port set in ConfigFile.properties
    for contSplit in arrayContainersInstances:
        # adminPort.extend(config.get('AppContainerSection', contSplit + '_adm_port'))
        if 'gw' in contSplit:
            appPort = config.get('GatewayContainerSection', contSplit + '_app_port')
        elif 'SIL' in contSplit:
            appPort = config.get('AppContainerSection', contSplit + '_app_port')

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        result = sock.connect_ex((serverAddress, int(appPort)))
        if result == 0:
            print contSplit + ' ' + str(result)
        else:
            print contSplit + ' ' + str(result)


# ######################
# Function clusterValidate -- Execute Cluster validation in Fuse containers
# #################################################################33
def clusterValidate():
    serverAddress = config.get('RootContainerSection', 'serverAddress')
    rootContainer = config.get('RootContainerSection', 'rootContainer')
    jlkUserName = config.get('RootContainerSection', 'jlkUserName')
    jlkUserPassword = config.get('RootContainerSection', 'jlkUserPassword')
    admPort = config.get('RootContainerSection', rootContainer + '_adm_port')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    result = sock.connect_ex((serverAddress, int(admPort)))
    if result == 0:
        try:
            j4p = Jolokia('http://' + serverAddress + ':' + admPort + '/jolokia/')
            j4p.auth(httpusername=decode(jlkUserName), httppassword=decode(jlkUserPassword))
            strClusterStatus = j4p.request(type='read', mbean='io.fabric8:service=Health', attribute='CurrentStatus')
            if strClusterStatus['value'] == 'Good':
                clusterStatus = 0
            else:
                clusterStatus = 1
        except Exception:
            clusterStatus = 1
    else:
        clusterStatus = 1
    print rootContainer + ' ' + str(clusterStatus)


# ######################
# Function zookeeperValidate -- Execute Zookeeper validation in Fuse root containers
# #################################################################33
def zookeeperValidate():
    serverAddress = config.get('RootContainerSection', 'serverAddress')
    rootContainer = config.get('RootContainerSection', 'rootContainer')
    jlkUserName = config.get('RootContainerSection', 'jlkUserName')
    jlkUserPassword = config.get('RootContainerSection', 'jlkUserPassword')
    admPort = config.get('RootContainerSection', rootContainer + '_adm_port')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    result = sock.connect_ex((serverAddress, int(admPort)))
    if result == 0:
        try:
            j4p = Jolokia('http://' + serverAddress + ':' + admPort + '/jolokia/')
            j4p.auth(httpusername=decode(jlkUserName), httppassword=decode(jlkUserPassword))
            reqZookeeperStatus = j4p.request(type='read', mbean='org.apache.zookeeper:name0=*,name1=*', attribute='State')
            strZookeeperStatus = reqZookeeperStatus['value'].items()[0][1]['State']
            if strZookeeperStatus == 'following' or strZookeeperStatus == 'leading':
                zookeeperStatus = 0
            else:
                zookeeperStatus = 1
        except Exception:
            zookeeperStatus = 1
    else:
        zookeeperStatus = 1
    print rootContainer + ' ' + str(zookeeperStatus)


# ######################
# Function apacheCamelValidate -- Execute Apache Camel validation in Fuse application containers
# #################################################################33
def apacheCamelValidate():
    serverAddress = config.get('RootContainerSection', 'serverAddress')
    appContainers = config.get('AppContainerSection', 'appContainers')
    jlkUserName = config.get('RootContainerSection', 'jlkUserName')
    jlkUserPassword = config.get('RootContainerSection', 'jlkUserPassword')

    arrayContainersInstances = []
    arrayContainersInstances.extend(appContainers.split(','))

    for contSplit in arrayContainersInstances:
        admPort = config.get('AppContainerSection', contSplit + '_adm_port')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        result = sock.connect_ex((serverAddress, int(admPort)))
        if result == 0:
            try:
                j4p = Jolokia('http://' + serverAddress + ':' + admPort + '/jolokia/')
                j4p.auth(httpusername=decode(jlkUserName), httppassword=decode(jlkUserPassword))
                reqApacheCamelStatus = j4p.request(type='read', mbean='org.apache.camel:context=*,type=context,name=*',
                                                   attribute='State')
                strApacheCamelStatus = reqApacheCamelStatus['value'].items()[0][1]['State']

                if strApacheCamelStatus == 'Started':
                    apacheCamelStatus = 0
                else:
                    apacheCamelStatus = 1
            except Exception:
                apacheCamelStatus = 1
        else:
            apacheCamelStatus = 1
        print contSplit + ' ' + str(apacheCamelStatus)


# ######################
# Function activeMQValidate -- Execute Apache Camel validation in Fuse application containers
# #################################################################33
def activeMQValidate():
    serverAddress = config.get('RootContainerSection', 'serverAddress')
    appContainers = config.get('AppContainerSection', 'appContainers')
    jlkUserName = config.get('RootContainerSection', 'jlkUserName')
    jlkUserPassword = config.get('RootContainerSection', 'jlkUserPassword')

    arrayContainersInstances = []
    arrayContainersInstances.extend(appContainers.split(','))

    for contSplit in arrayContainersInstances:
        admPort = config.get('AppContainerSection', contSplit + '_adm_port')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        result = sock.connect_ex((serverAddress, int(admPort)))
        if result == 0:
            try:
                j4p = Jolokia('http://' + serverAddress + ':' + admPort + '/jolokia/')
                j4p.auth(httpusername=decode(jlkUserName), httppassword=decode(jlkUserPassword))

                reqActiveMQStatus = j4p.request(type='read', \
                                                mbean='org.apache.activemq:brokerName=' + contSplit + ',service=Health,type=Broker', \
                                                attribute='CurrentStatus')
                strActiveMQStatus = reqActiveMQStatus['value']
                if strActiveMQStatus == 'Good':
                    activeMQStatus = 0
                else:
                    activeMQStatus = 1
            except Exception:
                activeMQStatus = 1
        else:
            activeMQStatus = 1
        print contSplit + ' ' + str(activeMQStatus)


# ######################
# Function servicesValidation -- Execute ApacheCXF services validation in Fuse application containers
# #################################################################33
def servicesCXFValidation():
    serverAddress = config.get('RootContainerSection', 'serverAddress')
    appContainers = config.get('AppContainerSection', 'appContainers')
    jlkUserName = config.get('RootContainerSection', 'jlkUserName')
    jlkUserPassword = config.get('RootContainerSection', 'jlkUserPassword')

    arrayContainersInstances = []
    arrayContainersInstances.extend(appContainers.split(','))

    for contSplit in arrayContainersInstances:
        admPort = config.get('AppContainerSection', contSplit + '_adm_port')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        result = sock.connect_ex((serverAddress, int(admPort)))
        if result == 0:
            try:
                j4p = Jolokia('http://' + serverAddress + ':' + admPort + '/jolokia/')
                j4p.auth(httpusername=decode(jlkUserName), httppassword=decode(jlkUserPassword))

                reqApacheCXFStatus = j4p.request(type='read',
                                                 mbean='io.fabric8.cxf:*,instance.id=*,port=*,service=*,type=Bus.Service.Endpoint',
                                                 attribute='State')
                serviceCXFStatus = 0
                for apacheCXF in reqApacheCXFStatus['value'].items():
                    splitApacheCXF = apacheCXF[0].split(',')
                    apacheCXFState = apacheCXF[1]
                    splitApacheCXFApp = str(splitApacheCXF[2]).split('=')
                    apacheCXFApp = splitApacheCXFApp[1].replace('"', '')
                    statusCXF = str(apacheCXFApp) + '=' + str(apacheCXFState['State'])

                    if ("STARTED" not in statusCXF):
                        serviceCXFStatus = serviceCXFStatus + 1
            except Exception:
                serviceCXFStatus = serviceCXFStatus + 1

        print contSplit + ' ' + str(serviceCXFStatus)


# ######################
# Function userDefinition -- Set user and password properties to access Jolokia(JMX) Interface
# #################################################################33
def userDefinition():

    userName = raw_input('Input JBoss Fuse admin user name: ')
    userPassword = getpass.getpass('Input JBoss Fuse admin password: ')
    usrNameEncoded = encode(userName)
    usrPasswordEncoded = encode(userPassword)
    print 'Insert the values at conf/ConfigFile.properties at RootContainerSection \n'
    print 'jlkUserName = ' + usrNameEncoded + ' -- ' + 'jlkUserPassword = ' + usrPasswordEncoded


def encode(strEncode):
    key = 'WebDXC'
    enc = []
    for i in range(len(strEncode)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(strEncode[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc))


def decode(strEncode):
    key = 'WebDXC'
    dec = []
    strEncode = base64.urlsafe_b64decode(strEncode)
    for i in range(len(strEncode)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(strEncode[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


# ######################
# Function help --help or -h
# #################################################################33
def help():
    print "AdminPortStatus: Show admin port status for all containers in ConfigFile.properties\n" \
          "AppPortStatus: Show application port status for all application containers in ConfigFile.properties\n" \
          "UsageMemoryAvg: Show average memory usage for each container in ConfigFile.properties\n" \
          "ClusterStatus: Show Cluster status for root container in ConfigFile.properties\n" \
          "ZookeeperStatus: Show Zookeeper status for root container in ConfigFile.properties\n" \
          "ApacheCamelStatus: Show Apache Camel status for each application container in ConfigFile.properties\n" \
          "ActiveMQStatus: Show ActiveMQ status for each application in ConfigFile.properties\n" \
          "WebServicesStatus: Show Apache CXF status for each application container in ConfigFile.properties\n" \
          "UserConfig: Encrypt user and password to be included in ConfigFile.properties\n"
    print "Execute ./fuse-stats.py -m \n" \
          "<AdminPortStatus|AppPortStatus|UsageMemoryAvg|ClusterStatus|ZookeeperStatus|ApacheCamelStatus|ActiveMQStatus|WebServicesStatus|UserConfig>"


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hm", ["help", "metric="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        help()
        sys.exit(2)
    metric = None
    for o, a in opts:
        if o == "-s":
            verbose = True
        elif o in ("-h", "--help"):
            help()
            sys.exit(2)
        elif o in ("-m", "--metric") and args[0] == "AdminPortStatus":
            portValidate()
        elif o in ("-m", "--metric") and args[0] == "AppPortStatus":
            appPortValidate()
        elif o in ("-m", "--metric") and args[0] == "UsageMemoryAvg":
            memoryUsageStatus()
        elif o in ("-m", "--metric") and args[0] == "ClusterStatus":
            clusterValidate()
        elif o in ("-m", "--metric") and args[0] == "ZookeeperStatus":
            zookeeperValidate()
        elif o in ("-m", "--metric") and args[0] == "ApacheCamelStatus":
            apacheCamelValidate()
        elif o in ("-m", "--metric") and args[0] == "ActiveMQStatus":
            activeMQValidate()
        elif o in ("-m", "--metric") and args[0] == "WebServicesStatus":
            servicesCXFValidation()
        elif o in ("-m", "--metric") and args[0] == "UserConfig":
            userDefinition()
        else:
            help()


if __name__ == "__main__":
    main()
