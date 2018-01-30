using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Diagnostics;
using System.IO;

namespace EventlogparserReDo
{
    class Program
    {
        static void Main(string[] args)
        {
            Stopwatch bigtimer = new Stopwatch(); //timer for runtime statistics
            bigtimer.Start();

            Values values = new Values();

            string[] rawfilelist = Directory.GetFileSystemEntries(@".\", "*.evtx", SearchOption.TopDirectoryOnly);
            
            List<Thread> threadlist = new List<Thread>();
            for(int count= 0; count < rawfilelist.Length; count++)
            {
                Thread temp = new Thread(() => { values.Ingester(Path.GetFullPath(rawfilelist[count])); });
                temp.Start();

                threadlist.Add(temp);
                while(threadlist.Count > 50) // thread generation throttle
                {
                    threadlist[0].Join();
                    threadlist.RemoveAt(0);
                }
            }
            while (threadlist.Count > 0) // concluding ingester phase
            {
                threadlist[0].Join();
                threadlist.RemoveAt(0);
            }

            bigtimer.Stop();
            TimeSpan rundurationraw = bigtimer.Elapsed;

            Console.WriteLine("Runtime " + rundurationraw);
            Console.WriteLine("Press any key to exit");
            Console.ReadLine();
        }
    }
}
