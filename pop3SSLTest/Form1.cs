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
            if (pop3.login("pop.gmail.com", 995, "testemail@gmail.com", "password"))
            {
                textBox1.AppendText("Login Successful\n");
            }
            else
            {
                textBox1.AppendText("Login FAILED!\n");
                return;
            }
            if (pop3.stat())
            {
                textBox1.AppendText("STAT");
                textBox1.AppendText("numMessages: " + pop3.NumMessages.ToString() + "\n");
                textBox1.AppendText("size: " + pop3.SizeOctet.ToString() + "\n");
            }
            
            if (pop3.list(pop3.NumMessages))
            {
                textBox1.AppendText("LIST ");
                textBox1.AppendText("msgID: " + pop3.MsgId.ToString() + "\n");
                textBox1.AppendText("size: " + pop3.MsgSize.ToString() + "\n");
            }
            
            if (pop3.retr(pop3.NumMessages))
            {
                textBox1.AppendText("RETR Success\n");
                for ( i = 0; i < pop3.responseLength(); i++)
                    textBox1.AppendText(pop3.responseString(i));
            }
            
            if (pop3.noop())
            {
                textBox1.AppendText("NOOP Success\n");
                for (; i < pop3.responseLength(); i++)
                    textBox1.AppendText(pop3.responseString(i));
            }

            if (pop3.dele(pop3.NumMessages))
            {
                textBox1.AppendText("DELE Success\n");
                for (; i < pop3.responseLength(); i++)
                    textBox1.AppendText(pop3.responseString(i));
            }

            if (pop3.rset())
            {
                textBox1.Text += "RSET Success";
                for (; i < pop3.responseLength(); i++)
                    textBox1.AppendText(pop3.responseString(i));
            }
 
            if (pop3.logout())
                textBox1.AppendText("Logout Success!\n");
            else
                textBox1.AppendText("Logout FAILED!\n");
        }

        
        

        
    }
}
