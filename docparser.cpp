/*
File: docparser.cpp
Date: 3/24/18
Author: Kyle Shake

Purpose: Parse documents related to Packet Sniffer program
*/

#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
using namespace std;





int main(int argc, char* argv[]){
    
   
    ifstream infile;
    infile.open(argv[1]);

    string fileline;

    int prevsec = 0;   
    int currdatasize;
    vector <int> datatotalsPERsec;
    int datatotal = 0;


    if(infile.fail()){
        cout << "ERROR: File not found!" << endl;
    }
    else{
        while(!infile.eof()){
            getline(infile, fileline);

            if(fileline == "") 		break;

            size_t pos = 0;
            string token;
            string delimiter = " ";
	    


            vector <string> tokens;
            while((pos = fileline.find(delimiter)) != string::npos){
                token = fileline.substr(0, pos);
                fileline = fileline.substr(pos+1, string::npos);
                tokens.push_back(token);
            }

            char* p;
            if(tokens[0] == ""){
                tokens.erase(tokens.begin());
            }    
            currdatasize = strtol(tokens[0].c_str(), &p, 10);
            cout << "Current data size is " << currdatasize << endl;

            string timestring = tokens[5];
            string timetoken;
            string delimiter2 = ":";
            size_t pos2 = 0;
            vector <string> timetokens;
            while((pos2 = timestring.find(delimiter2)) != string::npos){
                timetoken = timestring.substr(0, pos2);
                timestring = timestring.substr(pos2+1, string::npos);
                timetokens.push_back(timetoken);
            }

            timetokens.push_back(timestring);
            char* p2;
 

            int seconds = strtol(timetokens[2].c_str(), &p2, 10);
            cout << "Current second marker is " << seconds << endl;


            if(prevsec == 0){
                prevsec = seconds;
                datatotal += currdatasize;
                cout << "Adding " << currdatasize << " to data total at " << seconds;
                cout << " second marker" << endl;
            }else if(prevsec == seconds){
                datatotal += currdatasize;
                cout << "Adding " << currdatasize << " to data total at " << seconds;
                cout << " second marker" << endl;
                cout << "Current data total is " << datatotal << " at " << seconds;
                cout << " second marker." << endl;
            }else if(prevsec != seconds){
                cout << "Pushing back data total " << datatotal << " for " << prevsec;
                cout << " second marker." << endl;
                datatotalsPERsec.push_back(datatotal);
      
                cout << "Second marker is now " << seconds << endl;
                datatotal = currdatasize;
                cout << "New data total is " << datatotal << endl;
                prevsec = seconds;                
            }
            
            tokens.clear();
            timetokens.clear();

        } //END WHILE(!infile.eof);
    
        datatotalsPERsec.push_back(datatotal);
        infile.close();

    } //END ELSE

    ofstream outfile;
    outfile.open("ParsedData.txt");

    for(int i = 0; i < datatotalsPERsec.size(); i++){
        cout << i << "\t" << datatotalsPERsec[i] << endl;
        outfile << i << "\t" << datatotalsPERsec[i] << endl;

    }
    outfile.close();


}
