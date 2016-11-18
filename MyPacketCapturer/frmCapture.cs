using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using PacketDotNet;
using SharpPcap;
using System.Net;
using System.Xml.Linq;
using System.Xml;
using System.IO;
using System.Collections.Specialized;

namespace MyPacketCapturer
{
    public partial class frmCapture : Form
    {
        CaptureDeviceList devices; //List of devices for this computer
        public static ICaptureDevice device; //The device we will be using
        public static string stringPackets = ""; //Data that is captured
        static int numPackets;
        static int numUDP;
        static int numARP;
        public static string stringLocation = "";
        public static string stringInfo = "";
        frmSend fSend; //This will be our send form
        
        public frmCapture()
        {
            InitializeComponent();

            //Get the list of devices
            devices = CaptureDeviceList.Instance;

            //Make sure there is at least one device
            if (devices.Count < 1)
            {
                MessageBox.Show("No capture devices found!!");
                Application.Exit();
            }
            //Add the devices to the combo box
            foreach(ICaptureDevice dev in devices)
            {
                cmbDevices.Items.Add(dev.Description);
            }
            
            //Get the second device and display in combo box
            device = devices[0];
            cmbDevices.Text = device.Description;

            //Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(device_OnPacketArrival);

            //Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous,readTimeoutMilliseconds);
            
        }
       
        //God bless StackOverflow
        public static string GetCountryByIP(string ipAddress)
        {
            string strReturnVal;
            string ipResponse = IPRequestHelper("http://ip-api.com/xml/" + ipAddress);

            //return ipResponse;
            XmlDocument ipInfoXML = new XmlDocument();
            ipInfoXML.LoadXml(ipResponse);
            XmlNodeList responseXML = ipInfoXML.GetElementsByTagName("query");
            

            NameValueCollection dataXML = new NameValueCollection();
            try
            {
                dataXML.Add(responseXML.Item(0).ChildNodes[2].InnerText, responseXML.Item(0).ChildNodes[2].Value);//Country


                strReturnVal = "PACKET LOCATED AT: " + responseXML.Item(0).ChildNodes[5].InnerText.ToString();// City
                strReturnVal += ","+responseXML.Item(0).ChildNodes[4].InnerText.ToString()+" ";//State
                strReturnVal += "(" +responseXML.Item(0).ChildNodes[2].InnerText.ToString() + ")";//Country
                return strReturnVal;
            }
            catch
            {
                string strERROR = "";
                return strERROR;
            }
            
        }

        public static string IPRequestHelper(string url)
        {

            HttpWebRequest objRequest = (HttpWebRequest)WebRequest.Create(url);
            HttpWebResponse objResponse = (HttpWebResponse)objRequest.GetResponse();

            StreamReader responseStream = new StreamReader(objResponse.GetResponseStream());
            string responseRead = responseStream.ReadToEnd();

            responseStream.Close();
            responseStream.Dispose();

            return responseRead;
        }

        private static void device_OnPacketArrival(object sender, CaptureEventArgs packet)
        {
            
            var time = packet.Packet.Timeval.Date;
            var len = packet.Packet.Data.Length;

            var packetx = PacketDotNet.Packet.ParsePacket(packet.Packet.LinkLayerType, packet.Packet.Data);

            //Gathering the TCP packet data
            var tcpPacket = PacketDotNet.TcpPacket.GetEncapsulated(packetx);
            if (tcpPacket != null)
            {
                var ipPacket = (PacketDotNet.IpPacket)tcpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;

                //Print source and destination port
                stringInfo += "PACKET NUMBER: " + numPackets + " | " + "The TCP source port is: " + Convert.ToString(srcPort) + " and the TCP destination port is : " + Convert.ToString(dstPort);
                stringInfo += Environment.NewLine;

                //Print destination IP address
                stringInfo += "PACKET NUMBER: " + numPackets + " | " + "The TCP destination address is: " + Convert.ToString(dstIp);
                stringInfo += Environment.NewLine;

                //Print length of packet
                stringInfo += "PACKET NUMBER: " + numPackets + " | " + "The length of the packet is: " + len;
                stringInfo += Environment.NewLine;

                //Limit the number of location requests since the API only allows for 150 requests/min
                if (numPackets % 30 == 0)
                {
                    
                    //Returns the location of the source IP address and time of arrival
                    string strTCPIP = Convert.ToString(srcIp);
                    if (strTCPIP.Contains("."))
                    {
                        stringLocation += "PACKET NUMBER: " + numPackets + " | " + "TCP IP: " + strTCPIP + " " + GetCountryByIP(strTCPIP) + " packet arrived at: " + time;
                        stringLocation += Environment.NewLine;
                    }
                }
                
               
            }
            //Gathering the UDP packet data
            var udpPacket = PacketDotNet.UdpPacket.GetEncapsulated(packetx);
            if (udpPacket != null)
            {
                var ipPacket = (PacketDotNet.IpPacket)udpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = udpPacket.SourcePort;
                int dstPort = udpPacket.DestinationPort;

                //Print source and destination port
                stringInfo += "PACKET NUMBER: " + numPackets+ " | " + "The UDP source port is: " + Convert.ToString(srcPort) + " and the UDP destination port is : " + Convert.ToString(dstPort);
                stringInfo += Environment.NewLine;

                //Print destination IP address
                stringInfo += "PACKET NUMBER: " + numPackets + " | " + "The UDP destination address is: " + Convert.ToString(dstIp);
                stringInfo += Environment.NewLine;

                //Print length of packet
                stringInfo += "PACKET NUMBER: " + numPackets + " | " + "The length of the packet is: " + len;
                stringInfo += Environment.NewLine;

                //Limits the number of location requests since the API only allows for 150 requests/min
                if (numPackets % 30 == 0)
                {
                    //Returns the location of the source IP addresses and time of arrival
                    string strUDPIP = Convert.ToString(srcIp);
                    if (strUDPIP.Contains("."))
                    {
                        stringLocation += "PACKET NUMBER: " + numPackets + "| " + "UDP IP: " + strUDPIP + " " + GetCountryByIP(strUDPIP) + " packet arrived at: " + time;
                        stringLocation += Environment.NewLine;
                    }
                }
            }
            
            //Increment the number of packets captured
            numPackets++;
            
            //Put the packet number in the capture window
            stringPackets += "Packet Number: " + Convert.ToString(numPackets);
            stringPackets += Environment.NewLine;
          
            //Array to store our data
            byte[] data = packet.Packet.Data;
            
            
            //Keep track of the number of bytes displayed per line
            int byteCounter = 0;

            
            stringPackets += "Destination Mac Address";
            //Parsing the packets
            
            stringPackets += Environment.NewLine;
            foreach (byte b in data)
            {
                
                //Add the byte to our string (in hexadecimal)
                if(byteCounter<=13) stringPackets += b.ToString("X2") + " ";
                byteCounter++;
                
                switch (byteCounter)
                {
                    case 6: stringPackets += Environment.NewLine;
                        stringPackets += "Source MAC Address: ";
                        break;
                    case 12: stringPackets += Environment.NewLine;
                        stringPackets += "EtherType: ";
                        break;
                    case 14: if(data[12]==8)
                        {
                            if (data[13] == 0)
                            {
                                numUDP++; 
                                stringPackets += "(IP)";
                            }
                            if (data[13] == 6)
                            {
                                numARP++; 
                                stringPackets += "(ARP)";
                            }
                        }
                    
                        stringPackets += Environment.NewLine;
                        break;
                    
                }
                
            }
            

            

            stringPackets += Environment.NewLine + Environment.NewLine;
            byteCounter = 0;
            stringPackets += "Raw Data" + Environment.NewLine;
            //Process each byte in our captured packet
            foreach (byte b in data)
            {
                
                //Add the byte to our string (in hexadecimal)
                stringPackets += b.ToString("X2") + " ";
                byteCounter++;
                
                
                //adds a new line so it doesn't run over
                if (byteCounter == 16)
                {
                    byteCounter = 0;
                    stringPackets += Environment.NewLine;
                }
            }
            stringPackets += Environment.NewLine;
            stringPackets += Environment.NewLine;
           
        }
        
        private void btnStartStop_Click(object sender, EventArgs e)
        {
            
            try
            {
                if(btnStartStop.Text == "Start")
                {
                    device.StartCapture();
                    timer1.Enabled = true;
                    btnStartStop.Text = "Stop";
                }
                else
                {
                    device.StopCapture();
                    timer1.Enabled = false;
                    btnStartStop.Text = "Start";
                }
            }
            catch (Exception exp)
            {

            }
        }

        //Dump the packet data from stringPackets to the text box
        private void timer1_Tick(object sender, EventArgs e)
        {
            txtCapturedData.AppendText(stringPackets);
            stringPackets = "";
           txtNumPackets.Text = Convert.ToString(numPackets);

           txtLocation.AppendText(stringLocation);
           stringLocation = "";

           txtInfo.AppendText(stringInfo);
           stringInfo = "";

           txtNumUDP.Text = Convert.ToString(numUDP);

           //Calculate the percentage of packets for each type
           if (numPackets > 0)
           {
               double numUDPP = numUDP * 100.0 / numPackets;
               double numARPP = numARP * 100.0 / numPackets;
               txtPercentUDP.Text = Convert.ToString(Math.Round(numUDPP,2))+"%";
               txtPercentARP.Text = Convert.ToString(Math.Round(numARPP,2))+"%";
           }
           txtNumARP.Text = Convert.ToString(numARP);
          
           

        }

        private void cmbDevices_SelectedIndexChanged(object sender, EventArgs e)
        {
            device = devices[cmbDevices.SelectedIndex];
            cmbDevices.Text = device.Description;

            txtGUID.Text = device.Name;

            //Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(device_OnPacketArrival);

            //Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
        }

        private void saveToolStripMenuItem_Click(object sender, EventArgs e)
        {
            saveFileDialog1.Filter = "Text Files| *.txt|All Files|*.*";
            saveFileDialog1.Title = "Save the captured packets";
            saveFileDialog1.ShowDialog();

            //Check to see if a filename was given
            if(saveFileDialog1.FileName!="")
            {
                System.IO.File.WriteAllText(saveFileDialog1.FileName, txtCapturedData.Text);
            }
        }

        private void openToolStripMenuItem_Click(object sender, EventArgs e)
        {
            openFileDialog1.Filter = "Text Files| *.txt|All Files|*.*";
            openFileDialog1.Title = "Open the captured packets";
            openFileDialog1.ShowDialog();

            //Check to see if a filename was given
            if (openFileDialog1.FileName != "")
            {
                txtCapturedData.Text = System.IO.File.ReadAllText(openFileDialog1.FileName);
            }
        }

        private void sendWindowToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (frmSend.instantiations == 0)
            {
                fSend = new frmSend(); //Creates a new frmSend
                fSend.Show();                
            }           
        }
    }
}
