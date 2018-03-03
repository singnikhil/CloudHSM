package com.amazonaws.cloudhsm.examples.keystore;
import java.security.Signature;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.List;

import com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample;
import com.cavium.key.CaviumRSAPrivateKey;

import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

public class FileSignExample implements SignatureInterface
{
    private Certificate[] certificateChain;
    private PrivateKey privateKey;
    private boolean externalSigning = false;

    public static void main(String[] args) {
		System.out.println("I Rule!");
		LoginLogoutExample.loginWithExplicitCredentials();
		System.out.println("Getting Private Key");
		FileSignExample obj =  new FileSignExample();
		obj.createSignatureBase();
		InputStream is;
		try {
			is = new FileInputStream(new File("/home/ec2-user/OpenID_BootCamp_v3.pdf"));
			byte[] signature = obj.sign(is);
			System.out.println(Base64.getEncoder().encodeToString(signature));
			OutputStream output = new FileOutputStream("/home/ec2-user/OpenID_BootCamp_v3_signed.pdf");
			PDDocument doc = PDDocument.load(new FileInputStream(new File("/home/ec2-user/OpenID_BootCamp_v3.pdf")));
			obj.signDetached( doc,  output);
			output.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		LoginLogoutExample.logout();
	}
    
    public void createSignatureBase() {
		KeyStoreExample obj = new KeyStoreExample();
    	CaviumRSAPrivateKey privKey = obj.getPrivateKey("clientAuthRSAPrivKey");
    	setPrivateKey(privKey);
		Certificate[] certChain = obj.getCertificate("/home/ec2-user/", "clientAuth.crt");
		setCertificateChain(certChain);
		Certificate cert = certChain[0];
         if (cert instanceof X509Certificate)
         {
             // avoid expired certificate
             try {
				((X509Certificate) cert).checkValidity();
			} catch (CertificateExpiredException | CertificateNotYetValidException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
         }
    }
    
    
    public void signDetached(PDDocument document, OutputStream output)
            throws IOException
    {
        // create signature dictionary
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("Example User");
        signature.setLocation("Los Angeles, CA");
        signature.setReason("Testing");

        // the signing date, needed for valid signature
        signature.setSignDate(Calendar.getInstance());


        if (isExternalSigning())
        {
            System.out.println("Sign externally...");
            document.addSignature(signature);
            ExternalSigningSupport externalSigning =
                    document.saveIncrementalForExternalSigning(output);
            // invoke external signature service
            byte[] cmsSignature = sign(externalSigning.getContent());
            // set signature bytes received from the service
            externalSigning.setSignature(cmsSignature);
        }
        else
        {
            SignatureOptions signatureOptions = new SignatureOptions();
            // Size can vary, but should be enough for purpose.
            signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
            // register signature dictionary and sign interface
            document.addSignature(signature, this, signatureOptions);

            // write incremental (only for signing purpose)
            document.saveIncremental(output);
        }
    }

    public byte[] sign(InputStream content) throws IOException
    {
        // cannot be done private (interface)
        try
        {
            List<Certificate> certList = new ArrayList<>();
            certList.addAll(Arrays.asList(certificateChain));
            Store certs = new JcaCertStore(certList);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            org.bouncycastle.asn1.x509.Certificate cert = org.bouncycastle.asn1.x509.Certificate.getInstance(certificateChain[0].getEncoded());
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(sha1Signer, new X509CertificateHolder(cert)));
            gen.addCertificates(certs);
            CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
            CMSSignedData signedData = gen.generate(msg, false);
            //#TODO Add tsaURL Functionality
            /*if (tsaUrl != null && tsaUrl.length() > 0)
            {
                ValidationTimeStamp validation = new ValidationTimeStamp(tsaUrl);
                signedData = validation.addSignedTimeStamp(signedData);
            }*/
            return signedData.getEncoded();
        }
        catch (GeneralSecurityException | CMSException | OperatorCreationException e)
        {
            throw new IOException(e);
        }
    }
    
	public Certificate[] getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(Certificate[] certificateChain) {
		this.certificateChain = certificateChain;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
	class CMSProcessableInputStream implements CMSTypedData
	{
	    private InputStream in;
	    private final ASN1ObjectIdentifier contentType;

	    CMSProcessableInputStream(InputStream is)
	    {
	        this(new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId()), is);
	    }

	    CMSProcessableInputStream(ASN1ObjectIdentifier type, InputStream is)
	    {
	        contentType = type;
	        in = is;
	    }

	    @Override
	    public Object getContent()
	    {
	        return in;
	    }

	    @Override
	    public void write(OutputStream out) throws IOException, CMSException
	    {
	        // read the content only one time
	        IOUtils.copy(in, out);
	        in.close();
	    }

	    @Override
	    public ASN1ObjectIdentifier getContentType()
	    {
	        return contentType;
	    }
	}
    public void setExternalSigning(boolean externalSigning)
    {
        this.externalSigning = externalSigning;
    }
    public boolean isExternalSigning()
    {
        return externalSigning;
    }
}
