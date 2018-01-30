using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;

namespace EventlogparserReDo
{
    class Values
    {

        //ingester lists
        List<EventRecord> log21;
        List<EventRecord> log22;
        List<EventRecord> log23;
        List<EventRecord> log24;
        List<EventRecord> log25;
        List<EventRecord> log1149;
        List<EventRecord> log4624;
        List<EventRecord> log4634;
        List<EventRecord> logother;
        List<EventRecord>[] logs;
        //intel and correlations
        List<IPAddress> IPlist;



        public Values()
        {
            log21 = new List<EventRecord>();
            log22 = new List<EventRecord>();
            log23 = new List<EventRecord>();
            log24 = new List<EventRecord>();
            log25 = new List<EventRecord>();
            log1149 = new List<EventRecord>();
            log4624 = new List<EventRecord>();
            log4634 = new List<EventRecord>();
            logother = new List<EventRecord>();
            logs = new List<EventRecord>[] { log21, log22, log23, log24, log25, log1149, log4624, log4634, logother };

            IPlist = new List<IPAddress>();
        }
        
        public void Ingester(string filepath)
        {
            string logname = (Path.GetFileName(filepath)).Split('.')[0];

            using (EventLogReader reader = new EventLogReader(filepath, PathType.FilePath))
            {
                EventRecord record;
                while ((record = reader.ReadEvent()) != null)
                {
                    switch (record.Id)
                    {
                        case 21:
                            log21.Add(record);
                            break;
                        case 22:
                            log22.Add(record);
                            break;
                        case 23:
                            log23.Add(record);
                            break;
                        case 24:
                            log24.Add(record);
                            break;
                        case 25:
                            log25.Add(record);
                            break;
                        case 1149:
                            log1149.Add(record);
                            break;
                        case 4624:
                            log4624.Add(record);
                            break;
                        case 4634:
                            log4634.Add(record);
                            break;
                        default:
                            logother.Add(record);
                            break;
                    }
                }
            }
        }

        public void IPgatherer()
        {


            List<Thread> threadlist = new List<Thread>();
            Regex IP4 = new Regex(@"((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])",RegexOptions.IgnoreCase);
            Regex IP6 = new Regex(@"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))",RegexOptions.IgnoreCase);
            for (int count= 0; count < logs.Length; count++)
            {
                Thread temp = new Thread(() =>
                {
                    for (int counter = 0; counter < logs[count].Count; count++)
                    {
                        MatchCollection ip = IP4.Matches(logs[count][counter].Properties.ToString());
                        
                        
                    }
                });
            }
        }
        public void OSInt()
        {

        }
    }
}
