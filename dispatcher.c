/*-------------------------------------------------------------------------------
Final PA: Enhanced Needham-Shroeder Protocol Implementation

FILE:   dispatcher.c

Written By: 
     1- Matt Ladany
Submitted on: December 3, 2017
-------------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "wrappers.h"

#define   READ_END	0
#define   WRITE_END	1
#define   STDIN  0
#define   STDOUT 1
//--------------------------------------------------------------------------
int main( int argc , char *argv[] )
{
    pid_t  amalPID , basimPID , kdcPID;

   // Amal to Basim control and data pipes
    int    AtoKDC_ctrl[2] , KDCtoA_ctrl[2] , AtoB_ctrl[2] , BtoA_ctrl[2] ,
           AtoB_iv[2] , AtoB_data[2] ;

    char   arg1[20] , arg2[20] , arg3[20] , arg4[20] , arg5[20] , arg6[20];

    Pipe( AtoKDC_ctrl ) ;   // create pipe for Amal-to-KDC control
    Pipe( KDCtoA_ctrl ) ;   // create pipe for KDC-to-Amal control
    Pipe( AtoB_ctrl ) ;     // create pipe for Amal-to-Basim control
    Pipe( BtoA_ctrl ) ;     // create pipe for Basim-to-Amal control
    Pipe( AtoB_iv   ) ;     // create a pipe for Amal-To-Basim IV
    Pipe( AtoB_data ) ;     // create pipe for Amal-to-Basim data

    printf("\nDispatcher started and created these pipes\n") ;
    printf("Amal-to-KDC   control pipe: read=%d  write=%d\n", AtoKDC_ctrl[READ_END] , AtoKDC_ctrl[WRITE_END] ) ;
    printf("KDC-to-Amal   control pipe: read=%d  write=%d\n", KDCtoA_ctrl[READ_END] , KDCtoA_ctrl[WRITE_END] ) ;
    printf("Amal-to-Basim control pipe: read=%d  write=%d\n", AtoB_ctrl[READ_END] , AtoB_ctrl[WRITE_END] ) ;
    printf("Basim-to-Amal control pipe: read=%d  write=%d\n", BtoA_ctrl[READ_END] , BtoA_ctrl[WRITE_END] ) ;
    printf("Amal-to_Basim data iv pipe: read=%d  write=%d\n", AtoB_iv[READ_END] , AtoB_iv[WRITE_END]);
    printf("Amal-to-Basim data    pipe: read=%d  write=%d\n", AtoB_data[READ_END] , AtoB_data[WRITE_END] ) ;

    // Create both child processes:
    amalPID = Fork() ;
    if ( amalPID == 0 )
    {    
        // This is the Amal process.
        // Amal will not use these ends of the pipes, decrement their 'count'
        close( AtoKDC_ctrl[READ_END] ) ;
        close( KDCtoA_ctrl[WRITE_END] ) ;
        close( AtoB_ctrl[READ_END]  ) ;
        close( BtoA_ctrl[WRITE_END] ) ;
        close( AtoB_iv[READ_END] ) ;
        close( AtoB_data[READ_END]  ) ;
        
        // Prepare the file descriptors as args to Amal
        snprintf( arg1 , 20 , "%d" , AtoKDC_ctrl[WRITE_END] ) ;
        snprintf( arg2 , 20 , "%d" , KDCtoA_ctrl[READ_END] ) ;
        snprintf( arg3 , 20 , "%d" , AtoB_ctrl[WRITE_END] ) ;
        snprintf( arg4 , 20 , "%d" , BtoA_ctrl[READ_END] ) ;
        snprintf( arg5 , 20 , "%d" , AtoB_iv[WRITE_END] ) ;
        snprintf( arg6 , 20 , "%d" , AtoB_ctrl[WRITE_END] ) ;
        
        // Now, Start Amal
        char * cmnd = "./amal/amal" ;
        execlp( cmnd , "Amal" , arg1 , arg2 , arg3 , arg4 , arg5 , arg6 , NULL );

        // the above execlp() only returns if an error occurs
        perror("ERROR starting Amal" );
        exit(-1) ;
    } 
    else
    {   
        kdcPID = Fork();

        if (kdcPID == 0 ) {
            close(AtoKDC_ctrl[WRITE_END]);
            close(KDCtoA_ctrl[READ_END]);
            close( AtoB_ctrl[READ_END] ) ; close ( AtoB_ctrl[WRITE_END] );
            close( BtoA_ctrl[READ_END] ) ; close ( BtoA_ctrl[WRITE_END] );
            close( AtoB_iv[READ_END] ) ; close ( AtoB_iv[WRITE_END] );
            close( AtoB_data[READ_END] ) ; close ( AtoB_data[WRITE_END] );


            snprintf( arg1 , 20 , "%d" , AtoKDC_ctrl[READ_END]);
            snprintf( arg2 , 20 , "%d" , KDCtoA_ctrl[WRITE_END]);

            execlp("./kdc/kdc", "KDC", arg1, arg2, NULL);

            perror("ERROR starting KDC");
            exit(-1);
        } else {

            // This is still the Dispatcher process 
            basimPID = Fork() ;
            if ( basimPID == 0 )
            {  
                // This is the Basim process
                // Basim will not use these ends of the pipes, decrement their 'count'
                close( AtoKDC_ctrl[READ_END] ) ; close ( AtoKDC_ctrl[WRITE_END] );
                close( KDCtoA_ctrl[READ_END] ) ; close ( KDCtoA_ctrl[WRITE_END] );
                close( AtoB_ctrl[WRITE_END] ) ;
                close( BtoA_ctrl[READ_END] )  ;
                close( AtoB_iv[WRITE_END] ) ;
                close( AtoB_data[WRITE_END] ) ;
            
                // Prepare the file descriptors as args to Basim
                snprintf( arg1 , 20 , "%d" , AtoB_ctrl[READ_END] ) ;
                snprintf( arg2 , 20 , "%d" , BtoA_ctrl[WRITE_END] );
                snprintf( arg3 , 20 , "%d" , AtoB_iv[READ_END] ) ;
                snprintf( arg4 , 20 , "%d" , AtoB_data[READ_END] ) ;

                char * cmnd = "./basim/basim" ;
                execlp( cmnd , "Basim" , arg1 , arg2 , arg3, arg4 , NULL );

                // the above execlp() only returns if an error occurs
                perror("ERROR starting Basim" ) ;
                exit(-1) ;
            }
            else
            {   // This is still the parent Dispatcher  process
                // close all ends of the pipes so that their 'count' is decremented
                close( AtoKDC_ctrl[WRITE_END] ); 
                close( AtoKDC_ctrl[READ_END]  );
                close( KDCtoA_ctrl[WRITE_END] ); 
                close( KDCtoA_ctrl[READ_END]  );   
                close( AtoB_ctrl[WRITE_END] ); 
                close( AtoB_ctrl[READ_END]  );   
                close( BtoA_ctrl[WRITE_END] ); 
                close( BtoA_ctrl[READ_END]  );   
                close( AtoB_iv[WRITE_END] ); 
                close( AtoB_iv[READ_END]  );
                close( AtoB_data[WRITE_END] ); 
                close( AtoB_data[READ_END]  );   

                printf("\nDispatcher is now waiting for KDC to terminate\n") ;
                waitpid( kdcPID, NULL, 0);
                
                printf("\nDispatcher is now waiting for Amal to terminate\n") ;
                waitpid( amalPID , NULL , 0 ) ;

                printf("\nDispatcher is now waiting for Basim to terminate\n") ;
                waitpid( basimPID , NULL , 0 ) ;

                printf("\nThe Dispatcher process has terminated\n") ;     
            }
        }
    }  
}

