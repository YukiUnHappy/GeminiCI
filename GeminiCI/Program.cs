using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace GeminiCI
{
    class Program
    {
        static WebClient webClient = new WebClient();

        static void Main(string[] args)
        {
            var w = Environment.GetEnvironmentVariable("WEB");

            webClient.DownloadFile(w, "m.ab");

            var p = Process.Start("..\\..\\..\\ManifestDump.exe", "m.ab");
            p.WaitForExit();

            var dic = new Dictionary<long, List<string>>();
            var mt = File.ReadAllText("manifest.txt");
            var r = new Regex("(hscenario/(\\d+?)_\\d_.+?)\\.");
            var ms = r.Matches(mt).Cast<Match>().AsParallel();
            foreach (var match in ms)
            {
                var id = long.Parse(match.Groups[2].Value);
                if (!dic.ContainsKey(id))
                    dic[id] = new List<string>();
                dic[id].Add(match.Groups[1].Value.Replace("hscenario/", "Hscenario/"));
                dic[id].Sort();
            }

            var text = JsonConvert.SerializeObject(dic);
            File.WriteAllText("ll.txt", text);

            Enc(Encoding.UTF8.GetBytes(text));

            Post();

            //Upload();
        }

        static void Enc(byte[] b)
        {
            var p = Environment.GetEnvironmentVariable("P");

            void DeriveKeyAndIV(string passphrase, byte[] salt, out byte[] key, out byte[] iv)
            {
                // generate key and iv
                var concatenatedHashes = new List<byte>(48);
                var password = Encoding.UTF8.GetBytes(passphrase);
                var currentHash = new byte[0];
                var md5 = MD5.Create();
                var enoughBytesForKey = false;

                // See http://www.openssl.org/docs/crypto/EVP_BytesToKey.html#KEY_DERIVATION_ALGORITHM
                while (!enoughBytesForKey)
                {
                    var preHashLength = currentHash.Length + password.Length + salt.Length;
                    var preHash = new byte[preHashLength];
                    Buffer.BlockCopy(currentHash, 0, preHash, 0, currentHash.Length);
                    Buffer.BlockCopy(password, 0, preHash, currentHash.Length, password.Length);
                    Buffer.BlockCopy(salt, 0, preHash, currentHash.Length + password.Length, salt.Length);
                    currentHash = md5.ComputeHash(preHash);
                    concatenatedHashes.AddRange(currentHash);
                    if (concatenatedHashes.Count >= 48)
                        enoughBytesForKey = true;
                }

                key = new byte[32];
                iv = new byte[16];

                concatenatedHashes.CopyTo(0, key, 0, 32);
                concatenatedHashes.CopyTo(32, iv, 0, 16);

                md5.Clear();
            }

            var s = new byte[8];
            new RNGCryptoServiceProvider().GetNonZeroBytes(s);
            DeriveKeyAndIV(p, s, out var k, out var i);

            using (var aes = Aes.Create())
            using (var encryptor = aes.CreateEncryptor(k, i))
            {
                var o = encryptor.TransformFinalBlock(b, 0, b.Length);

                var n = new byte[o.Length + 16];
                Buffer.BlockCopy(Encoding.ASCII.GetBytes("Salted__"), 0, n, 0, 8);
                Buffer.BlockCopy(s, 0, n, 8, 8);
                Buffer.BlockCopy(o, 0, n, 16, o.Length);

                File.WriteAllText("lm.txt", Convert.ToBase64String(n));
            }
        }

        static void Post()
        {
            var Key = Environment.GetEnvironmentVariable("KEY");

            webClient.Headers.Set("X-API-Key", Key);

            var Head = Environment.GetEnvironmentVariable("HEAD");

            var Do = Environment.GetEnvironmentVariable("DO");

            var rd = new Dictionary<string, object>();
            rd["target"] = Upload();
            rd["customurl"] = "gemini";
            rd["reuse"] = true;
            rd["domain"] = Do;

            webClient.Headers.Set(HttpRequestHeader.ContentType, "application/json");
            var u = JObject.Parse(webClient.UploadString($"{Head}api/v2/links", JsonConvert.SerializeObject(rd)));
        }

        static string Upload()
        {
            using (var client = new HttpClient())
            using (var formData = new MultipartFormDataContent())
            {
                formData.Headers.Add("filelength", "");
                client.DefaultRequestHeaders.Add("age", (7 * 24).ToString());

                formData.Add(new ByteArrayContent(File.ReadAllBytes("lm.txt")), "files[]", "file.txt");

                var response = client.PostAsync("https://safe.fiery.me/api/upload", formData).Result;

                // ensure the request was a success
                if (!response.IsSuccessStatusCode)
                {
                    return Upload();
                }

                var j = JObject.Parse(response.Content.ReadAsStringAsync().Result);

                return j["files"][0]["url"].ToString();
            }
        }
    }
}
