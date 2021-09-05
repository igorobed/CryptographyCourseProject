using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using Microsoft.Win32;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Numerics;
using System.ComponentModel;
using Ciphers;

namespace Alice
{
    public partial class MainWindow : Window
    {
        string pathFile = ""; //путь до выбранного файла
        string pathFolder = ""; //путь до папки с файлами
        string nameFolder = "FilesForSend";
        string nameFile = "";
        int state = 0; //программа только начала свою работу
        //алгоритмы шифрования
        ElGamal el;
        Magenta ma;
        byte[] IV; //вектор инициализации
        //длина ключей....в обоих клиентах длины должны совпадать
        int lengthKeyEl = 128;
        string remoteAddress = "127.0.0.1";// хост для отправки данных
        int remotePortConnection = 8004;// порт для отправки данных
        int remotePortDataFile = 8008;// порт для отправки данных
        int localPortConnection = 8003;// локальный порт для прослушивания входящих подключений
        int localPortDataFile = 8007;// локальный порт для прослушивания входящих подключений
        public MainWindow()
        {
            InitializeComponent();

            var dirStrs = Directory.GetCurrentDirectory().Split('\\');
            foreach (var str in dirStrs)
            {
                if (str == "bin")
                {
                    pathFolder += nameFolder;
                    break;
                }
                pathFolder += str + "\\";
            }

            //получение общего сессионного ключа
            Thread receiveThreadConnection = new Thread(new ThreadStart(ReceiveMessageConnection));
            receiveThreadConnection.Start();

            //получаем файл(данные) от друга
            //Thread receiveThreadDataFile = new Thread(new ThreadStart(ReceiveMessageDataFile));
            //receiveThreadDataFile.Start();
        }

        #region UDP methods
        private void SendMessageConnection()
        {
            UdpClient sender = new UdpClient(); //создаем UdpClient для отправки сообщений
            int len1BigInt = lengthKeyEl / 8 + 1; //максимальное число байтов на 1 бигинт
            try
            {
                if (state == 2) //если я прога, посылающая p, g и свой открытый ключ
                {
                    //я должен взять p, g и открытый ключ и привести их к одному размеру, сконкатенировать и передать

                    byte[] data = new byte[len1BigInt * 3];
                    BigInteger[] elKeysToSend = new BigInteger[3] { el.p, el.g, el.y };
                    for (int i = 0; i < 3; i++)
                    {
                        byte[] tempArrBytesBigInt = elKeysToSend[i].ToByteArray();
                        if (tempArrBytesBigInt.Length < len1BigInt)
                        {
                            Array.Resize(ref tempArrBytesBigInt, len1BigInt);
                        }
                        for (int j = 0; j < len1BigInt; j++)
                        {
                            data[i * len1BigInt + j] = tempArrBytesBigInt[j];
                        }
                    }
                    //и посылаю
                    state = 3; //отправил p и g + открытый ключ
                    sender.Send(data, data.Length, remoteAddress, remotePortConnection);
                }
                else if (state == 5)  //отправляю зашифрованный сессионный ключ для magenta
                {
                    //генерация ключа
                    byte[] maKey = new byte[16];
                    Random rand = new Random(Environment.TickCount);
                    rand.NextBytes(maKey);
                    //генерация вектора инициализации 
                    byte[] iv = new byte[16];
                    rand.NextBytes(iv);
                    //теперь шифрование с помощью эльгамаля и отправка
                    //ключ и вектор инициализации шифруются по отдельности, а после конкатенируются
                    BigInteger[] encMaKey = el.EncryptBytesArray(maKey); //17 бигинтов и нулевой - первая часть для всех ост
                    BigInteger[] encIV = el.EncryptBytesArray(iv); //17 бигинтов и нулевой - первая часть для всех ост
                    //теперь готовим это все для отправки в виде байтового массива
                    byte[] arrForSend = new byte[(encMaKey.Length + encIV.Length) * len1BigInt];
                    //сначала запишем сессионный ключ
                    for (int i = 0; i < encMaKey.Length; i++)
                    {
                        byte[] tempArrBytesBigInt = encMaKey[i].ToByteArray();
                        if (tempArrBytesBigInt.Length < len1BigInt)
                        {
                            Array.Resize(ref tempArrBytesBigInt, len1BigInt);
                        }
                        for (int j = 0; j < len1BigInt; j++)
                        {
                            arrForSend[i * len1BigInt + j] = tempArrBytesBigInt[j];
                        }
                    }
                    //потом запишем сгенерированный вектор инициализации
                    for (int i = 0; i < encIV.Length; i++)
                    {
                        byte[] tempArrBytesBigInt = encIV[i].ToByteArray();
                        if (tempArrBytesBigInt.Length < len1BigInt)
                        {
                            Array.Resize(ref tempArrBytesBigInt, len1BigInt);
                        }
                        for (int j = 0; j < len1BigInt; j++)
                        {
                            arrForSend[(i + 17) * len1BigInt + j] = tempArrBytesBigInt[j];
                        }
                    }
                    //создаем у себя объект magenta и пристваиваем ему соответствующий ключ + вектор инициализации
                    ma = new Magenta();
                    ma.FeistelRoundQuantity = 6;
                    ma.Key = maKey;
                    IV = iv;
                    //устанавливаю режим шифрования по умолчанию ECB, обновляем инфу и откр доступ к элементам
                    Action action = () =>
                    {
                        gbModes.IsEnabled = true;
                        rbECB.IsChecked = true;
                        labelKeyState.Content = "Сессионный ключ сгенерирован";
                        labelModeState.Content = "Режим шифрования - ECB";
                        buttonEnc.IsEnabled = true;
                        buttonDec.IsEnabled = true;
                        buttonSend.IsEnabled = true;
                    };
                    Dispatcher.Invoke(action);
                    //отправляю
                    state = 4;
                    sender.Send(arrForSend, arrForSend.Length, remoteAddress, remotePortConnection);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                sender.Close();
            }
        }

        private void ReceiveMessageConnection()
        {
            UdpClient receiver = new UdpClient(localPortConnection); // UdpClient для получения данных
            IPEndPoint remoteIp = null; // адрес входящего подключения
            int len1BigInt = lengthKeyEl / 8 + 1; //максимальное число байтов на 1 бигинт
            try
            {
                while (true)
                {
                    //если мы пока еще от него ничего не получали и считаем, что он пока еще не тыкнул кнопку установки соединения
                    byte[] data = receiver.Receive(ref remoteIp); //получаем данные
                    if (data.Length / len1BigInt == 3)
                    {
                        //мы думаем, что нам пришел p, g и открытый ключ от друга
                        BigInteger[] bigIntInBytes = new BigInteger[data.Length / len1BigInt];
                        for (int i = 0; i < data.Length / len1BigInt; i++)
                        {
                            byte[] tempArrBytes = new byte[len1BigInt];
                            for (int j = 0; j < len1BigInt; j++)
                            {
                                tempArrBytes[j] = data[i * len1BigInt + j];
                            }
                            bigIntInBytes[i] = new BigInteger(tempArrBytes);
                        }

                        el = new ElGamal(bigIntInBytes[0], bigIntInBytes[1], lengthKeyEl);
                        el.friendPublicKey = bigIntInBytes[2];

                        state = 5; //я получил ключи эльгамаля от друга

                        //теперь Я автоматически должен сгенерировать и отправить ему зашифрованный ключ для мадженты
                        //генерация ключа, его шифрование и отправка в SendMessageConnection c условием, что state == 5
                        SendMessageConnection();
                    }
                    else
                    {
                        //или я получаю зашифрованный сессионный ключ для MAGENTA

                        //я получил массив байт длинной 34*len1BigInt
                        //мне над его расшифровать, создать объект шифратор magenta и задаему соответствующий ключ и вектор
                        //инициализации
                        BigInteger[] bigIntInBytes = new BigInteger[data.Length / len1BigInt];
                        for (int i = 0; i < data.Length / len1BigInt; i++)
                        {
                            byte[] tempArrBytes = new byte[len1BigInt];
                            for (int j = 0; j < len1BigInt; j++)
                            {
                                tempArrBytes[j] = data[i * len1BigInt + j];
                            }
                            bigIntInBytes[i] = new BigInteger(tempArrBytes);
                        }
                        //элемент под индексом 0 и 17 - первые части каждого зашифрованного байта следующего за ними из переданного сообщения
                        byte[] outStrBytesKey = new byte[bigIntInBytes.Length / 2 - 1];
                        byte[] outStrBytesIV = new byte[bigIntInBytes.Length / 2 - 1];
                        //сначала расшифруем ключ мадженты
                        for (int i = 1; i < bigIntInBytes.Length / 2; i++)
                        {
                            outStrBytesKey[i - 1] = (byte)el.Decrypt(bigIntInBytes[0], bigIntInBytes[i]);
                        }
                        //теперь расшифруем вектор инициализации
                        for (int i = 18; i < bigIntInBytes.Length; i++)
                        {
                            outStrBytesIV[i - 18] = (byte)el.Decrypt(bigIntInBytes[17], bigIntInBytes[i]);
                        }
                        //создаем объект magenta и записываем в него ключ
                        ma = new Magenta();
                        ma.FeistelRoundQuantity = 6;
                        ma.Key = outStrBytesKey;
                        IV = outStrBytesIV;
                        //устанавливаю режим шифрования по умолчанию ECB, обновляем инфу и откр доступ к элементам
                        Action action = () =>
                        {
                            gbModes.IsEnabled = true;
                            rbECB.IsChecked = true;
                            labelKeyState.Content = "Сессионный ключ сгенерирован";
                            labelModeState.Content = "Режим шифрования - ECB";
                            buttonEnc.IsEnabled = true;
                            buttonDec.IsEnabled = true;
                            buttonSend.IsEnabled = true;
                        };
                        Dispatcher.Invoke(action);

                        state = 9;//получил сессионный ключ для мадженты
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                receiver.Close();
            }
        }
        #endregion

        #region CONTROL methods
        private void ButtonSetConnection_Click(object sender, RoutedEventArgs e)
        {
            if (state == 0)
            {
                //эльгамаль генерируем p и g + свой отркрытый и закрытый ключи
                //другу я отправляю p, g, открытый ключ
                //он их получает и теперь может сгенерировать сессионный ключ для мадженты и с помощью моего
                //открытого ключа зашифровать эльгамалем ключ для мадженты и передать его мне
                //а я его уже расшифрую и у нас обоих будет одинаковый ключ для мадженты
                el = new ElGamal(lengthKeyEl);//p, g, открытый и закрытый ключи сгенерированны
                state = 2;//я начал отправку p, g и открытого ключа
                SendMessageConnection();
            }
            else if (state == 4 || state == 9)
            {
                MessageBox.Show("Соединение уже установленно.");
            }
            else
            {
                MessageBox.Show("Соединение устанавливается.");
            }
        }

        private void ButtonSelectFile_Click(object sender, RoutedEventArgs e)
        {
            pathFile = "";
            nameFile = "";

            OpenFileDialog myDialog = new OpenFileDialog();

            myDialog.CheckFileExists = true;

            myDialog.InitialDirectory = pathFolder;

            myDialog.Filter = "Текстовые файлы|*.txt";
            if (myDialog.ShowDialog() == true)
            {
                pathFile = myDialog.FileName;

            }
            if (pathFile != "")
            {
                string[] tempStrArr = pathFile.Split('\\');
                for (int i = 0; i < tempStrArr.Length; i++)
                {
                    if (i == (tempStrArr.Length - 1))
                    {
                        nameFile = tempStrArr[i];
                    }
                }
                fileText.Text = File.ReadAllText(pathFile, Encoding.Default);
                labelFileState.Content = "Файл выбран";
            }
            else
            {
                fileText.Text = "";
                labelFileState.Content = "Файл не выбран";
            }
        }
        private void ButtonEncryptFile_Click(object sender, RoutedEventArgs e)
        {

        }
        private void ButtonDecryptFile_Click(object sender, RoutedEventArgs e)
        {

        }
        private void ButtonSendFile_Click(object sender, RoutedEventArgs e)
        {

        }
        #endregion

        #region HELPER methods
        private void setDataToFile(string path, byte[] data)
        {
            using (FileStream fstream = new FileStream(path, FileMode.Create))
            {
                fstream.Write(data, 0, data.Length);
            }
        }

        private byte[] getDataFromFile(string path)
        {
            byte[] data;
            using (FileStream fstream = File.OpenRead(path))
            {
                data = new byte[fstream.Length];
                fstream.Read(data, 0, data.Length);
            }
            return data;
        }

        private byte[] getPercentsArray(int length)
        {
            float delta = (((float)100 / length));
            byte[] percents = new byte[length];
            //если дельты меньше 1
            //мне нужно отловить индексы, до которых мы переходим границу очередного целого числа
            if (delta < 1)
            {
                byte predPerc = 0;
                float deltSum = 0;
                byte currPercent = 0;
                for (int i = 0; i < percents.Length; i++)
                {
                    deltSum += delta;
                    if ((byte)deltSum != predPerc)
                    {
                        currPercent += 1;
                        predPerc = (byte)deltSum;
                    }
                    percents[i] = currPercent;
                }
            }
            else
            {
                byte deltSum = 0;
                for (int i = 0; i < percents.Length; i++)
                {
                    percents[i] = deltSum;
                    deltSum += (byte)delta;
                }
            }
            return percents;
        }

        //превращаем одномерный массив в двумерный зубчатый
        private byte[][] getArrayArraysForCipher(byte[] data)
        {
            byte[][] result;
            //byte[] tempData = data;
            if (data.Length <= 16)
            {
                result = new byte[1][];
                result[0] = data;
                Array.Resize(ref result[0], 16);
                return result;
            }
            else if ((data.Length > 16) && (data.Length % 16 == 0))
            {
                result = new byte[data.Length / 16][];
                for (int i = 0; i < data.Length / 16; i++)
                {
                    result[i] = new byte[16];
                    //копирование
                    for (int j = 0; j < 16; j++)
                    {
                        result[i][j] = data[i * 16 + j];
                    }
                }
                return result;
            }
            else
            {
                result = new byte[data.Length / 16 + 1][];
                for (int i = 0; i < data.Length / 16 + 1; i++)
                {
                    result[i] = new byte[16];
                    //если у нас последний цикл, значит в исходном массиве осталось не ровно 16 элементов, а меньше
                    if (i == data.Length / 16)
                    {
                        for (int j = 0; j < (data.Length - 16 * (data.Length / 16)); j++)
                        {
                            result[i][j] = data[i * 16 + j];
                        }
                    }
                    else
                    {
                        for (int j = 0; j < 16; j++)
                        {
                            result[i][j] = data[i * 16 + j];
                        }
                    }
                }
                return result;
            }
        }

        //разворачиваем зубчатый массив в одномерный
        private byte[] getArrayFromArrayArrays(byte[][] allBlocks)
        {
            byte[] result = new byte[allBlocks.Length * 16];
            for (int i = 0; i < allBlocks.Length; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    result[16 * i + j] = allBlocks[i][j];
                }
            }
            return result;
        }
        #endregion
    }
}
