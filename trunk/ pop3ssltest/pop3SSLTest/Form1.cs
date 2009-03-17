using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using pop3SSL;

namespace pop3SSLTest
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            textBox1.MaxLength = int.MaxValue;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            pop3C pop3 = new pop3C();
            int i = 0;
            if (pop3.login("pop.gmail.com", 995, "kallumama24@gmail.com", "mac802.11"))
            {
                textBox1.Text = "Login Success!\n";
            }
            else
            {
                textBox1.Text = "Login FAILED!\n";
                return;
            }
            if (pop3.stat())
            {
                textBox1.Text += "STAT";
                textBox1.Text += "numMessages: " + pop3.NumMessages.ToString() + "\n";
                textBox1.Text += "size: " + pop3.SizeOctet.ToString() + "\n";
            }
            
            if (pop3.list(1))
            {
                textBox1.Text += "LIST 397";
                textBox1.Text += "msgID: " + pop3.MsgId.ToString() + "\n";
                textBox1.Text += "size: " + pop3.MsgSize.ToString() + "\n";
            }
            
            if (pop3.retr(1))
            {
                textBox1.Text += "RETR Success";
                for ( i = 0; i < pop3.responseLength(); i++)
                    textBox1.Text += pop3.responseString(i);
            }

            if (pop3.noop())
            {
                textBox1.Text += "NOOP Success";
                for (; i < pop3.responseLength(); i++)
                    textBox1.Text += pop3.responseString(i);
            }

            if (pop3.dele(397))
            {
                textBox1.Text += "DELE Success";
                for (; i < pop3.responseLength(); i++)
                    textBox1.Text += pop3.responseString(i);
            }

            if (pop3.rset())
            {
                textBox1.Text += "RSET Success";
                for (; i < pop3.responseLength(); i++)
                    textBox1.Text += pop3.responseString(i);
            }
            if (pop3.logout())
                textBox1.Text += "Logout Success!\n";
            else
                textBox1.Text += "Logout FAILED!\n";
        }
    }
}
