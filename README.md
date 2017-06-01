package com.amazonaws.s3kms;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Properties;
import org.apache.logging.log4j.*;
import org.apache.logging.log4j.core.LoggerContext;
import junit.framework.Assert;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;

import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.regions.Region;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3EncryptionClient;
import com.amazonaws.services.s3.model.CryptoConfiguration;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.services.s3.model.KMSEncryptionMaterialsProvider;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.PutObjectResult;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.SSEAwsKeyManagementParams;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.HttpMethod;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.PutObjectRequest;

public class S3KMS {

private static String bucketName = null; 
private static String objectKey  = null; 
private static String kms_objectKey = null; 

private static String kms_cmk_id = null; 
private static String localFilePath = null;

private static AmazonS3EncryptionClient encryptionClient;
private static  Logger logger = null;
	    	
   public static void main(String[] args) throws Exception { 
	   
	   S3KMS s3KMSCore  = new S3KMS();	   
	   //Read Config info and update all key values
	   s3KMSCore.loadAppConfig();
	   
	   
	   //Upload the Encrypted File into S3
	   s3KMSCore.uploadEncryptedFile();
	   
	   //Generates a presigned URL with a time limit //Should be configurable
	   //s3KMSCore.getPreSignedURL();
	   
	   //Uploads into S3 post encryption
	   //s3KMSCore.uploadS3KMS();
	   
	   //Upload Simple Files from the program...
	   //s3KMSCore.simpleS3FileUpload();
   }
   
   private void uploadEncryptedFile() throws Exception {
     
        KMSEncryptionMaterialsProvider materialProvider = new KMSEncryptionMaterialsProvider(kms_cmk_id);
       
        encryptionClient = new AmazonS3EncryptionClient(new ProfileCredentialsProvider(), materialProvider,
                new CryptoConfiguration().withKmsRegion(Regions.US_EAST_1))
            .withRegion(Region.getRegion(Regions.US_EAST_1));
        
        // Upload object using the encryption client.
        byte[] plaintext = "S3 Client-side Encryption Using Asymmetric Master Key!"
                .getBytes();
        System.out.println("plaintext's length: " + plaintext.length);
        encryptionClient.putObject(new PutObjectRequest(bucketName, objectKey,
                new ByteArrayInputStream(plaintext), new ObjectMetadata()));

        // Download the object.
        S3Object downloadedObject = encryptionClient.getObject(bucketName,
                objectKey);
        byte[] decrypted = IOUtils.toByteArray(downloadedObject
                .getObjectContent());
        
        // Verify same data.
        Assert.assertTrue(Arrays.equals(plaintext, decrypted));
   }
 
   private void uploadS3KMS() throws Exception {
		AmazonS3Client s3 = new AmazonS3Client(new ProfileCredentialsProvider())
		        .withRegion(Region.getRegion(Regions.US_EAST_1));
	
		byte[] plaintext = "S3/KMS SSE Encryption - New!"
		            .getBytes(Charset.forName("UTF-8"));
		ObjectMetadata metadata = new ObjectMetadata();
		metadata.setContentLength(plaintext.length);
	
		PutObjectRequest req = new PutObjectRequest(bucketName, kms_objectKey,
		        new ByteArrayInputStream(plaintext), metadata)
		        .withSSEAwsKeyManagementParams(
		            new SSEAwsKeyManagementParams(kms_cmk_id));
		PutObjectResult putResult = s3.putObject(req);
		System.out.println(putResult);
	
		S3Object s3object = s3.getObject(bucketName, kms_objectKey);
		System.out.println(IOUtils.toString(s3object.getObjectContent()));
		s3.shutdown();	
   }
   
	private void getPreSignedURL() throws Exception {
		AmazonS3 s3client = new AmazonS3Client(new ProfileCredentialsProvider()); 
	       
		java.util.Date expiration = new java.util.Date();
		long msec = expiration.getTime();
		msec += 1000 * 60 * 60 * 2; // 2 hours.
		expiration.setTime(msec);
		             
		GeneratePresignedUrlRequest generatePresignedUrlRequest = 
		              new GeneratePresignedUrlRequest(bucketName, objectKey);
		generatePresignedUrlRequest.setMethod(HttpMethod.GET); // Default.
		generatePresignedUrlRequest.setExpiration(expiration);
		             
		URL s = s3client.generatePresignedUrl(generatePresignedUrlRequest); 
		System.out.println (s);
		
	}

	   private void simpleS3FileUpload() throws Exception {
		   
	        AmazonS3 s3client = new AmazonS3Client(new ProfileCredentialsProvider());
	        try {
	            System.out.println("Uploading a new object to S3 from a file\n");
	            File file = new File(localFilePath + objectKey);
	            s3client.putObject(new PutObjectRequest(
	            		                 bucketName, objectKey, file));

	         } catch (AmazonServiceException ase) {
	            System.out.println("Caught an AmazonServiceException, which " +
	            		"means your request made it " +
	                    "to Amazon S3, but was rejected with an error response" +
	                    " for some reason.");
	            System.out.println("Error Message:    " + ase.getMessage());
	            System.out.println("HTTP Status Code: " + ase.getStatusCode());
	            System.out.println("AWS Error Code:   " + ase.getErrorCode());
	            System.out.println("Error Type:       " + ase.getErrorType());
	            System.out.println("Request ID:       " + ase.getRequestId());
	        } catch (AmazonClientException ace) {
	            System.out.println("Caught an AmazonClientException, which " +
	            		"means the client encountered " +
	                    "an internal error while trying to " +
	                    "communicate with S3, " +
	                    "such as not being able to access the network.");
	            System.out.println("Error Message: " + ace.getMessage());
	        }

	   }
	   
	    /**
	     * LoadAppConfig
	     */
	    private void loadAppConfig() throws FileNotFoundException, Exception
	    {
	    	LoggerContext context = (LoggerContext) LogManager.getContext(false);
	        File file = new File("log4j2.xml");
	  
	        // this will force a reconfiguration
	        context.setConfigLocation(file.toURI());
	        logger = LogManager.getLogger("EC2EBSSnapMgmt");  
	        
	        String lPropertyFileName = "appconfig.properties";
	        try{

	        	Properties lAppProperties = new Properties();
	         	logger.info(" Property File name : " + lPropertyFileName);
	         	InputStream lInputStream = new FileInputStream(lPropertyFileName);
	         	
	           	if(lInputStream != null)
	        	{
	        		
	    			lAppProperties.load(lInputStream);
	 
	        		
	        		if(lAppProperties.getProperty("bucketName") != null)
	        		{
	        			bucketName = lAppProperties.getProperty("bucketName");
	        			logger.info("Requested bucketName are : " + bucketName);
	        		}
	        		if(lAppProperties.getProperty("objectKey") != null)
	        		{
	        			objectKey = lAppProperties.getProperty("objectKey");
	        			logger.info("objectKey : " + objectKey);
	        		}
	        		if(lAppProperties.getProperty("kms_objectKey") != null)
	        		{
	        			kms_objectKey = lAppProperties.getProperty("kms_objectKey");
	        			logger.info("kms_objectKey : " + kms_objectKey);
	        		}
	        		
	        		if(lAppProperties.getProperty("kms_cmk_id") != null)
	        		{
	        			kms_cmk_id = lAppProperties.getProperty("kms_cmk_id");
	        			logger.info("kms_cmk_id : " + kms_cmk_id);
	        		}
	        		
	        		if(lAppProperties.getProperty("localFilePath") != null)
	        		{
	        			localFilePath = lAppProperties.getProperty("localFilePath");
	        			logger.info("localFilePath : " + localFilePath);
	        		}
	      
	        		
	        	}

	        }
	        catch (FileNotFoundException ex)
	        {
	        	throw new FileNotFoundException("Property file '"+ lPropertyFileName +"' not found in the classpath");
	        }
	        catch (IOException ex){
	        	throw  new FileNotFoundException("Property file '"+ lPropertyFileName +"' not found in the classpath");

	        }

	    }
}
