#define  DEVICE_NAME "Mfirewall"
#define  CLASS_NAME  "fire"
#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <linux/uaccess.h>          // Required for the copy to user function
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/time.h>
#include <linux/fcntl.h>



MODULE_LICENSE("GPL");              ///< The license type -- this affects runtime behavior
MODULE_AUTHOR("mohammad saghali");      ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("packet Dropper LKM");  ///< The description -- see modinfo
MODULE_VERSION("1.0");              ///< The version of the module


static int    majorNumber;                   ///< Stores the device number -- determined automatically
static char   message[256] = {0};           ///< Memory for the string that is received from userspace
static struct class*  dropperClass  = NULL; ///< The device-driver class struct pointer
static struct device* dropperDevice = NULL; ///< The device-driver device struct pointer

// The prototype functions for the character driver -- must come before the struct definition
static int  dev_Open(struct inode *, struct file *);
static int  dev_release(struct inode *, struct file *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops ={
   .open = dev_Open,
   .write = dev_write,
   .release = dev_release,
};


unsigned int packetDropper_hook(unsigned int hooknum, struct sk_buff *skb,const struct net_device *in, const struct net_device *out,int(*okfn)(struct sk_buff *));

static struct nf_hook_ops packetDropper __read_mostly = {
        .pf = NFPROTO_IPV4,  // PF_INET;
        .priority = NF_IP_PRI_FIRST,
        .hooknum =NF_INET_LOCAL_IN,  // NF_INET_LOCAL_OUT;
        .hook = (nf_hookfn *) packetDropper_hook
};

int flag = 1;
int arrLength = 0;
char arr[100][25];


static int __init packetDropper_init(void){
   int ret;
   arrLength = 0;

   printk(KERN_INFO "packetdropper: Initializing the packetdropper LKM\n");

   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
     printk(KERN_ALERT "packetdropper failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "packetdropper: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   dropperClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(dropperClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(dropperClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "packetdropper: device class registered correctly\n");

   // Register the device driver
   dropperDevice = device_create(dropperClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(dropperDevice)){               // Clean up if there is an error
      class_destroy(dropperClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(dropperDevice);
   }
   printk(KERN_INFO "packetdropper: device class created correctly\n"); // Made it! device was

   printk(KERN_INFO "packet droper loaded\n");

   ret = nf_register_net_hook(&init_net,&packetDropper); /*Record in net filtering */
   if(ret)
      printk(KERN_INFO "FAILED");
   return  ret;
}

static void __exit  packetDropper_exit(void){
   device_destroy(dropperClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(dropperClass);                          // unregister the device class
   class_destroy(dropperClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
   printk(KERN_INFO "packetdropper: Goodbye from the LKM!\n");
//   printk(KERN_INFO "Bye icmp drop module unloaded\n");
   nf_unregister_net_hook(&init_net,&packetDropper); /*UnRecord in net filtering */
}

static int dev_Open(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "packetdropper: Device has been opened \n");
   return 0;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   error_count = copy_from_user(message, buffer, len); //catch message from tester
   if(!strncmp("blacklist",message,strlen("blacklist"))){
      printk(KERN_INFO "packetdropper: in blacklist config\n");
      arrLength=0;
      flag = 1;
   }
   else if(!strncmp("whitelist",message,strlen("whitelist"))){
      printk(KERN_INFO "packetdropper: in whitelist config\n");
      arrLength=0;
      flag = 0;
   }
   else{
     strncpy(arr[arrLength],message,strlen(message)-1);
      arrLength++;
      if(flag)
         printk(KERN_INFO "packetdropper: %s added to black list\n",arr[arrLength-1]);
      else
         printk(KERN_INFO "packetdropper:  %s added to white list\n",arr[arrLength-1]);
   }
   return len;
}

static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "packetdropper: Device successfully closed\n");
   return 0;
}


unsigned int packetDropper_hook(unsigned int hooknum, struct sk_buff *skb,const struct net_device *in, const struct net_device *out,int(*okfn)(struct sk_buff *)){

    int i;
    char address[25];
    struct iphdr *ipHeader = (struct iphdr *)skb_network_header(skb);
    struct tcphdr *tcpHeader;
    struct udphdr *udpHeader;
    unsigned int port = 0;

    struct timespec currentTime;
    getnstimeofday(&currentTime);



   if(!skb)
      return NF_DROP;

   if (ipHeader->protocol == 6) {
      tcpHeader = (struct tcphdr *)skb_transport_header(skb);
      port = (unsigned int)ntohs(tcpHeader->source);
   }
   else if (ipHeader->protocol==17){
     udpHeader = (struct udphdr *)skb_transport_header(skb);
     port = (unsigned int)ntohs(udpHeader->source);
   }
   sprintf(address, "%pI4:%u", &ipHeader->saddr, port);
   if(flag){
      for(i=0;i<arrLength ;i++){
         if(!strncmp(address,arr[i],strlen(address))){
            printk(KERN_DEBUG "(%.2lu:%.2lu:%.2lu) - packetdropper- %s DROP from black list",
                          (currentTime.tv_sec / 3600) % (24), //hour
                          (currentTime.tv_sec / 60) % (60), //minute
                          (currentTime.tv_sec) % 60 //second
                          ,address);
            return NF_DROP;
         }
        }
            printk(KERN_DEBUG "(%.2lu:%.2lu:%.2lu) - packetdropper- %s ACCEPET from black list",
                          (currentTime.tv_sec / 3600) % (24), //hour
                          (currentTime.tv_sec / 60) % (60), //minute
                          (currentTime.tv_sec) % 60 //second
                          ,address);

            return NF_ACCEPT;
   }
   else{
      for(i=0;i<arrLength ;i++){
      if(!strncmp(address,arr[i],strlen(address))){
            printk(KERN_DEBUG "(%.2lu:%.2lu:%.2lu) - packetdropper - ACCEPET %s  from white list",
                          (currentTime.tv_sec / 3600) % (24), //hour
                          (currentTime.tv_sec / 60) % (60), //minute
                          (currentTime.tv_sec) % 60 //second
                          ,address);
            return NF_ACCEPT;
         }
       }
      printk(KERN_DEBUG "(%.2lu:%.2lu:%.2lu) - packetdropper - DROP %s from white list",
                    (currentTime.tv_sec / 3600) % (24), //hour
                    (currentTime.tv_sec / 60) % (60), //minute
                    (currentTime.tv_sec) % 60 //second
                    ,address);
      return NF_DROP;
   }
   return NF_ACCEPT;

}
module_init(packetDropper_init);
module_exit(packetDropper_exit);
