    using System;
    using System.Collections;
    using System.Runtime.InteropServices;
    using System.Windows.Forms;

    using Microsoft.Web.Services.Security.X509;

    public class StoreDialog
    {
        X509CertificateStore store;

        public StoreDialog(X509CertificateStore store)
        {
            this.store = store;
        }

        static bool IsWinXP()
        {
            OperatingSystem os = Environment.OSVersion;
            Version v = os.Version;

            if ( os.Platform == PlatformID.Win32NT && v.Major >= 5 && v.Minor >= 1 )
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Displays a dialog that can be used to select a certificate from the store.
        /// </summary>
        public X509Certificate SelectCertificate(IntPtr hwnd, string title, string displayString)
        {
            if ( store.Handle == IntPtr.Zero )
                throw new InvalidOperationException("Store is not open");

            if ( IsWinXP() )
            {
                IntPtr certPtr = CryptUIDlgSelectCertificateFromStore(store.Handle, hwnd, title, displayString, 0/*dontUseColumn*/, 0 /*flags*/, IntPtr.Zero);
                if ( certPtr != IntPtr.Zero )
                {
                    return new X509Certificate(certPtr);
                }
            }
            else
            {
                SelectCertificateDialog dlg = new SelectCertificateDialog(store);
                if ( dlg.ShowDialog() != DialogResult.OK )
                {
                    return null;
                }
                else
                {
                    return dlg.Certificate;
                }
            }

            return null;
        }

        [DllImport("cryptui", CharSet=CharSet.Unicode, SetLastError=true)]
        internal extern static IntPtr CryptUIDlgSelectCertificateFromStore(IntPtr hCertStore, IntPtr hwnd, string pwszTitle, string pwszDisplayString, uint dwDontUseColumn, uint dwFlags, IntPtr pvReserved);
    }

    /// <summary>
    /// SelectCertificateDialog.
    /// </summary>
    class SelectCertificateDialog : System.Windows.Forms.Form
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.Windows.Forms.Button _okBtn;
        private System.Windows.Forms.Button _cancelBtn;

        private X509CertificateStore _store;
        private System.Windows.Forms.ListView _certList;
        private System.Windows.Forms.ColumnHeader _certName;
        private X509Certificate _certificate = null;

        public SelectCertificateDialog(X509CertificateStore store) : base()
        {
            _store = store;

            // Required for Windows Form Designer support
            //
            InitializeComponent();

            // Create columns for the items and subitems.
            _certList.Columns.Add("Name", 200, HorizontalAlignment.Left);
            _certList.Columns.Add("Issued By", -2, HorizontalAlignment.Left);
            _certList.Columns.Add("Full Name", -2, HorizontalAlignment.Left);
            _certList.Columns.Add("Certificate Identifier", -2, HorizontalAlignment.Left);
        }

        public X509Certificate Certificate
        {
            get
            {
                return _certificate;
            }
        }

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this._okBtn = new System.Windows.Forms.Button();
            this._cancelBtn = new System.Windows.Forms.Button();
            this._certList = new System.Windows.Forms.ListView();
            this._certName = new System.Windows.Forms.ColumnHeader();
            this.SuspendLayout();
            // 
            // _okBtn
            // 
            this._okBtn.Anchor = (System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right);
            this._okBtn.DialogResult = System.Windows.Forms.DialogResult.OK;
            this._okBtn.Location = new System.Drawing.Point(288, 256);
            this._okBtn.Name = "_okBtn";
            this._okBtn.TabIndex = 1;
            this._okBtn.Text = "OK";
            this._okBtn.Click += new System.EventHandler(this.OkBtn_Click);
            // 
            // _cancelBtn
            // 
            this._cancelBtn.Anchor = (System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right);
            this._cancelBtn.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this._cancelBtn.Location = new System.Drawing.Point(368, 256);
            this._cancelBtn.Name = "_cancelBtn";
            this._cancelBtn.TabIndex = 2;
            this._cancelBtn.Text = "Cancel";
            this._cancelBtn.Click += new System.EventHandler(this.CancelBtn_Click);
            // 
            // _certList
            // 
            this._certList.Anchor = (((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
                | System.Windows.Forms.AnchorStyles.Left) 
                | System.Windows.Forms.AnchorStyles.Right);
            this._certList.FullRowSelect = true;
            this._certList.MultiSelect = false;
            this._certList.Name = "_certList";
            this._certList.Size = new System.Drawing.Size(456, 248);
            this._certList.TabIndex = 3;
            this._certList.View = System.Windows.Forms.View.Details;
            // 
            // _certName
            // 
            this._certName.Text = "Name";
            this._certName.Width = 92;
            // 
            // SelectCertificateDialog
            // 
            this.AcceptButton = this._okBtn;
            this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
            this.CancelButton = this._cancelBtn;
            this.ClientSize = new System.Drawing.Size(456, 286);
            this.Controls.AddRange(new System.Windows.Forms.Control[] {
                                                                          this._certList,
                                                                          this._cancelBtn,
                                                                          this._okBtn});
            this.Name = "SelectCertificateDialog";
            this.Text = "SelectCertificateDialog";
            this.ResumeLayout(false);

        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            if ( _store == null )
            {
                throw new Exception("No store to open");
            }

            if ( _store.Handle == IntPtr.Zero )
            {
                throw new Exception("Store not open for reading");
            }

            X509CertificateCollection coll = _store.Certificates;

            foreach(X509Certificate cert in coll)
            {
                ListViewItem item = new CertificateListViewItem(cert);
                _certList.Items.Add(item);
            }
        }

        private void OkBtn_Click(object sender, System.EventArgs e)
        {
            _certificate = null;

            if ( _certList.SelectedItems != null && _certList.SelectedItems.Count == 1 )
            {                
                _certificate = ((CertificateListViewItem)_certList.SelectedItems[0]).Certificate;
            }

            this.Close();
            this.DialogResult = DialogResult.OK;
        }

        private void CancelBtn_Click(object sender, System.EventArgs e)
        {
            _certificate = null;
            this.DialogResult = DialogResult.Cancel;
        }

        class CertificateListViewItem : ListViewItem
        {
            X509Certificate cert;

            public CertificateListViewItem(X509Certificate certificate) : base(GetSubItems(certificate))
            {
                cert = certificate;
            }

            static string GetCommonName(string name)
            {
                if (name == null || name.Length == 0)
                {
                    return string.Empty;
                }

                string [] fields = name.Split(',');
                for (int i = 0; i < fields.Length; i++)
                {
                    string field = fields[i];
                    if (field == null)
                        break;
                    
                    field = field.Trim();
                    if (field.StartsWith("CN="))
                    {
                        return field.Substring(3);
                    }
                }
                return "<Common Name not found>";
            }

            static string[] GetSubItems(X509Certificate certificate)
            {
                string issuedTo = certificate.GetName();
                string issuedBy = GetCommonName(certificate.GetIssuerName());
                string certKeyId = Convert.ToBase64String(certificate.GetKeyIdentifier());

                string simpleName = GetCommonName(issuedTo);                

                return new string [] { simpleName, issuedBy, issuedTo, certKeyId };
            }

            public X509Certificate Certificate
            {
                get
                {
                    return cert;
                }
            }
        }
    }

