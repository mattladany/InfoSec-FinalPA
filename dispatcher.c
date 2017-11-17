/*-------------------------------------------------------------------------------
PA-02: Messaage Digest & Signature using Pipes

FILE:   dispatcher.c

Written By: 
     1- Dr. Mohamed Aboutabl
Submitted on: 
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
    pid_t  amalPID , basimPID ; 
    int    AtoB_ctrl[2] , AtoB_data[2] ;  // Amal to Basim control and data pipes
    char   arg1[20] , arg2[20] ;
    
    Pipe( AtoB_ctrl ) ;  // create pipe for Amal-to-Basim control
    Pipe( AtoB_data ) ;  // create pipe for Amal-to-Basim data

    printf("\nDispatcher started and created these pipes\n") ;
    printf("Amal-to-Basim control pipe: read=%d  write=%d\n", AtoB_ctrl[READ_END] , AtoB_ctrl[WRITE_END] ) ;
    printf("Amal-to-Basim data    pipe: read=%d  write=%d\n", AtoB_data[READ_END] , AtoB_data[WRITE_END] ) ;

    // Create both child processes:
    amalPID = Fork() ;
    if ( amalPID == 0 )
    {    
        // This is the Amal process.
        // Amal will not use these ends of the pipes, decrement their 'count'
        close( AtoB_ctrl[READ_END]  ) ;
        close( AtoB_data[READ_END]  ) ;
        
        // Prepare the file descriptors as args to Amal
        snprintf( arg1 , 20 , "%d" , AtoB_ctrl[WRITE_END] ) ;
        snprintf( arg2 , 20 , "%d" , AtoB_data[WRITE_END] ) ;
        
        // Now, Start Amal
        char * cmnd = "./amal/amal" ;
        execlp( cmnd , "Amal" , arg1 , arg2 , NULL );

        // the above execlp() only returns if an error occurs
        perror("ERROR starting Amal" );
        exit(-1) ;      
    } 
    else
    {    // This is still the Dispatcher process 
        basimPID = Fork() ;
        if ( basimPID == 0 )
        {  
            // This is the Basim process
            // Basim will not use these ends of the pipes, decrement their 'count'
            close( AtoB_ctrl[WRITE_END] ) ;
            close( AtoB_data[WRITE_END] ) ;
            
            // Prepare the file descriptors as args to Basim
            snprintf( arg1 , 20 , "%d" , AtoB_ctrl[READ_END] ) ;
            snprintf( arg2 , 20 , "%d" , AtoB_data[READ_END] ) ;

            char * cmnd = "./basim/basim" ;
            execlp( cmnd , "Basim" , arg1 , arg2 , NULL );

            // the above execlp() only returns if an error occurs
            perror("ERROR starting Basim" ) ;
            exit(-1) ;
        }
        else
        {   // This is still the parent Dispatcher  process
            // close all ends of the pipes so that their 'count' is decremented
            close( AtoB_ctrl[WRITE_END] ); 
            close( AtoB_ctrl[READ_END]  );   
            close( AtoB_data[WRITE_END] ); 
            close( AtoB_data[READ_END]  );   

            printf("\nDispatcher is now waiting for Amal to terminate\n") ;
            waitpid( amalPID , NULL , 0 ) ;

            printf("\nDispatcher is now waiting for Basim to terminate\n") ;
            waitpid( basimPID , NULL , 0 ) ;

            printf("\nThe Dispatcher process has terminated\n") ;     
        }
    }  
}

