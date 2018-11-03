
//! Jacopone
//!
//!	`jacopone` contains tools for encryption and decryption using Jacopone algorithm
//!
//!
//!
//!
#[macro_use]
extern crate crunchy;
extern crate crypto;
extern crate crossbeam;

mod jacopone;
mod cipherdata;

pub use self::jacopone::*;
pub use self::cipherdata::*;



#[cfg(test)]
mod tests {
	use crate::jacopone::*;
	use crate::CipherData;

    

    #[test]
    fn check_decryption() {
        let message = vec![
        "qwertyuiopaoidwboeiurw3iurb9823yec9unidjn0qu309ne8nqiuwdnicuqwec",
        "dfiauyer0uwqn309rny 0987wqemd9um0981u2m30xiqwjd'ci123',e98xu'm12983e",
        "owuenr9uc0n43nyrc08732nrc09u1n0re9iumx01i2jemx91u23098xun0u4yrc0n87134r",
        "iuwyer8nucn8urmc9q8uewnhrcq0iwe,d0xqw3u0m980m5w9wlxqwokdjmz09u4nr098u0n",
        "huiwrunf0u4r0n89374nt098uwne0iujnc0qiwjnpkasjnoiuwn09r8unc209843unc0983",
        "98u0nw9er8u0ntklkmcoaksdmcapslkejoksjdpfoijanc4oinrcq98wu4nr98qwu4nr98wqerwertwet4cqwkenciuqwercewqr",
        "iush0nfiuIUBIUB=UInisdnjoifjnc984un98un?)IUN)(A=)(UN£soiu'nqiwunriuqnwd9iubqcw98eunc98qwyebc098ybewq",
        "usane'rnu'0kd',qxewxewqrcoqweriunoq0we9run9823b98nwef9q8weurr98qw98y2983ye9898798798710987efsa918",
        "oiasdupfoiuwneoirunwoijfpwoeijfpowijepfoijcqwevivajacoponeisaofdiuwenoirunq9w8urn98wqrw8ercn'q9w8uer",
        "osreuqn4983nrc98uwqeokjx1'9238u'nce98u1438ur'981u32'e9'958u9ciwjelkfjc owejfoi32ur9cmqiwjeocqweprcoiquewrpociuqwpeoriucnpoiwquerncpoiqwe",
        "iusporijnoisjdfpoijernmc985t'109u43'imrc'okw1ldkewopkmrc0918430i1mw'eoirkmc'0i1wem'r0icm10923mrc1'0iewkrmc'0943mrc'093mr0934m'r09um'owie",
        "j09weiutm09mxlk'o3imrci12'38uc091y30497rync0iwjernokcqwierc0iwqeurncoiweurc0oiqwu98u5nc98u2n34098nrcoi324jorcwqeèrqèwpoiemcpoim4pircpwei",
        "'i'09riq'0w9ir'09iw'e09ir'09iwemr9icmq09rewim0i213me98c 32948nc1'2983u4n'092134n'c0918234n'c9821n3409128n3409c8n1'2384cn1'2kez,o321ie'z0",
        "09u34'r9ijc2'mrc'i432mr'lk'qwòqw,ò,òz<xpokwpdkqwèdò.w.eàrwerjcweoriucq209u09qw3iur09qwepokpweokcpqwkerpockpwqekrpo12i3u'upowjerlfkjweprk"
        ];

        let nonce = vec![
        vec![1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0],
        vec![99,43,12,43,65,23,65,87,1,98,9,8,7,6,5,4,3,2,1,54,0,87,98,1,45,87,32,8,34,2,34,34,76,32,176,87,231,22,201,234,63,76,9,76,87,1,3,4,8,54,32,13,98,56,44,33,76,54,34,65],
        vec![98,43,21,43,45,65,09,87,6,54,32,21,43,65,87,43,43,76,98,45,43,32,87,65,45,34,32,12,32,43,43,35,76,201,123,222,43,90,12,22,54,76,88,1,3,43,123,54,187,45,3,3,98,00,2,2,4,5,65,8],
        vec![1,32,54,66,223,241,27,98,43,5,9,55,99,76,43,21,6,89,5,44,6,5,33,8,23,87,33,98,23,87,1,0,9,0,0,223,65,23,65,132,102,23,65,6,32,6,78,43,5,67,1,23,98,4,34,7,2,54,76,9],
        ];

        let key = vec![
        vec![12,45,98,43,1,32,65,99,1,43,76,98,12,98,43,65,12,45,98,43,1,32,65,99,1,43,76,98,12,98,43,65],
        vec![10,7,21,33,32,76,54,45,12,87,09,12,43,87,43,23,44,21,33,32,76,54,45,2,0,87,09,12,43,87,43,23],
        ];

        let counter = vec![5432452,5,441234,1234,1234,23452,0,2345,4325,234,52,345,1234,5123,5,658,569,706,784,56,343,4,52,346769879,434352345,2345234,534];
        let jacopone = Jacopone::new(4);
        for i in 0..message.len() {
        	for j in 0..nonce.len(){
        		for h in 0..key.len(){
        			for t in 0..counter.len(){
						let nonce = (&nonce[j]).to_vec();
						let key = (&key[h]).to_vec();
						let counter: u64 = counter[t];
        	    		let data = CipherData::new((&message[i]).as_bytes().to_vec(), key.clone(), nonce.clone(), counter);
						let ciphertext = jacopone.encrypt(data);
    		        	let data = CipherData::new(ciphertext, key, nonce, counter);
            	
						let plaintext = jacopone.encrypt(data);

        				assert_eq!(&message[i].as_bytes().to_vec(), &plaintext);
        			}
        		}
        	}
    	}
    }

    

    
}
