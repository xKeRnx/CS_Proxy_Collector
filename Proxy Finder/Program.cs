using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MySql.Data.MySqlClient;

namespace Proxy_Finder
{
    class Program
    {
        static WebClient wc = new WebClient();
        static int found = 0;
        static int added = 0;
        static int updated = 0;
        static MySqlConnection conn;
        static MySqlCommand cmd = new MySqlCommand();

        static string table;

        static void Main(string[] args)
        {
            DateTime now = DateTime.Now;
            var MyIni = new IniFile("Settings.ini");
            if (!MyIni.KeyExists("server", "MySQL"))
            {
                MyIni.Write("server", "localhost", "MySQL");
            }
            if (!MyIni.KeyExists("user", "MySQL"))
            {
                MyIni.Write("user", "KeRn", "MySQL");
            }
            if (!MyIni.KeyExists("password", "MySQL"))
            {
                MyIni.Write("password", "*****", "MySQL");
            }
            if (!MyIni.KeyExists("database", "MySQL"))
            {
                MyIni.Write("database", "test", "MySQL");
            }
            if (!MyIni.KeyExists("table", "MySQL"))
            {
                MyIni.Write("table", "pub", "MySQL");
            }
            if (!MyIni.KeyExists("port", "MySQL"))
            {
                MyIni.Write("port", "3306", "MySQL");
            }

            var server = MyIni.Read("server", "MySQL");
            var user = MyIni.Read("user", "MySQL");
            var password = MyIni.Read("password", "MySQL");
            var database = MyIni.Read("database", "MySQL");
            table = MyIni.Read("table", "MySQL");
            var port = MyIni.Read("port", "MySQL");

            string connStr = "server="+ server + ";user="+ user + ";database="+ database + ";port="+ port + ";password="+ password;
            conn = new MySqlConnection(connStr);
            try
            {
                Console.WriteLine("Connecting to MySQL...");
                conn.Open();
                if (conn.State.ToString() == "Open")
                {
                    WriteLine(@"Connection working...", ConsoleColor.Green);

                    while (true)
                    {
                        now = DateTime.Now;
                        Console.WriteLine("Starting scan: " + now.ToString("yyyy-MM-dd HH:mm:ss"));
                        if (File.Exists(@"proxies.txt"))
                        {
                            string line;
                            StreamReader file = new StreamReader(@"proxies.txt");
                            while ((line = file.ReadLine()) != null)
                            {
                                line = line.ToLower();
                                if (!line.StartsWith("#") && line.StartsWith("h"))
                                {
                                    //Console.WriteLine("Check URL: " + line);
                                    if (UrlChecker(line))
                                    {
                                        //Console.WriteLine("worked....");
                                        findproxys(line);
                                    }
                                }
                            }
                            now = DateTime.Now;
                            WriteLine("Scan finish: " + now.ToString("yyyy-MM-dd HH:mm:ss"), ConsoleColor.Green);
                            WriteLine("found:" + found + " updated:" + updated + " added:" + added, ConsoleColor.Green);
                        }
                        else
                        {
                            WriteLine("ERROR: " + now.ToString("yyyy-MM-dd HH:mm:ss"), ConsoleColor.Red);
                            WriteLine("proxies.txt not exists!!!", ConsoleColor.Red);
                        }
                        Console.WriteLine("Waiting 3 hours for next scan...");
                        Thread.Sleep(10800000);
                    }
                }
                else
                {
                    WriteLine(@"Please check connection string", ConsoleColor.Red);
                }

            }
            catch (Exception ex)
            {
                WriteLine(ex.ToString(), ConsoleColor.Red);
            }

            conn.Close();


            Console.ReadLine();
        }

        static int select(string ip)
        {
            try
            {
                cmd = new MySqlCommand("SELECT COUNT(*) FROM " + table + " WHERE ip=(@ip)", conn);
                cmd.Parameters.AddWithValue("@ip", ip);
                cmd.Prepare();

                object result = cmd.ExecuteScalar();
                cmd.Dispose();
                if (result != null)
                {
                    int r = Convert.ToInt32(result);
                    return r;
                }

            }
            catch (Exception ex)
            {
                cmd.Dispose();
            }

            return 0;
        }

        static bool insert(string ip, int port)
        {
            try
            {
                cmd = new MySqlCommand("INSERT INTO " + table + "(ip, port) VALUES(@ip, @port)", conn);
                cmd.Parameters.AddWithValue("@ip", ip);
                cmd.Parameters.AddWithValue("@port", port);
                cmd.Prepare();

                int a = cmd.ExecuteNonQuery();
                cmd.Dispose();
                if (a > 0)
                {
                    added++;
                    return true;
                }

            }
            catch (Exception ex)
            {
                WriteLine(ex.ToString(), ConsoleColor.Red);
                Thread.Sleep(910800000);
            }

            return false;
        }

        static bool update(string ip)
        {
            try
            {
                MySqlCommand cmd = new MySqlCommand();
                cmd = new MySqlCommand("UPDATE " + table + " SET scan = NOW() WHERE ip = @ip", conn);
                cmd.Parameters.AddWithValue("@ip", ip);
                cmd.Prepare();

                int a = cmd.ExecuteNonQuery();
                cmd.Dispose();
                if (a > 0)
                {
                    updated++;
                    return true;
                }

            }
            catch (Exception ex)
            {
                cmd.Dispose();
                return false;
            }

            return false;
        }

        public static bool UrlChecker(string url)
        {
            Uri uriResult;
            bool tryCreateResult = Uri.TryCreate(url, UriKind.Absolute, out uriResult);
            if (tryCreateResult == true && uriResult != null)
                return true;
            else
                return false;
        }

        static void findproxys(string url)
        {
            try
            {
                string proxies = wc.DownloadString(url);
                // method 0: No tricks
                ExtractProxies(proxies);
                // method 1: find ip and port separated with a space or tab
                //ExtractProxies(Regex.Replace(proxies, @"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[\t ]+([0-9]+)", @"$1:$2"));
                // method 2: find port and ip separated with a space or tab
                //ExtractProxies(Regex.Replace(proxies, @"([0-9]+)[\t ]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", @"$1:$2"));
                // method 3: find ip and port separated with a space or tab, and the ip ends in ":"
                //ExtractProxies(Regex.Replace(proxies, @"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):[\t ]+([0-9]+)", @"$1:$2"));

                // More agresive, but methods that may give bad data.
                // method 4: find ip and port separated with spmthin other then 0-9
                //ExtractProxies(Regex.Replace(proxies, @"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[^0-9]+([0-9]+)", @"$1:$2"));
            }
            catch
            {

            }

        }

        static void WriteLine(string text, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ResetColor();
        }

        static void ExtractProxies(string result)
        {
            foreach (Match match in Regex.Matches(result, @"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\:[0-9]{1,5}\b"))
            {
                string[] server = match.Value.Split(':');

                if (select(server[0]) == 0)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Add proxie to DB : " + server[0]);
                    Console.ResetColor();
                    insert(server[0], Convert.ToInt32(server[1]));
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Update proxie in DB : " + server[0]);
                    Console.ResetColor();
                    update(server[0]);
                }

                found++;
            }
        }
    }
}
