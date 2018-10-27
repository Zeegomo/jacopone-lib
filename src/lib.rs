
//! Jacopone
//!
//!	'jacopone' contains tools for encryption and decryption using Jacopone algorithm
//!
//!
//!
//!

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
        let jacopone = Jacopone::new(4);
        for i in 0..message.len() {
			let nonce = vec![1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0];
			let key = vec![10, 7, 21, 33, 32, 76, 54, 45, 12, 87, 09, 12, 43, 87, 43 ,23, 44, 21, 33, 32, 76, 54, 45, 12, 87, 09, 12, 43, 87, 43 ,23, 44];
			let counter: u64 = 54;
            let data = CipherData::new((&message[i]).as_bytes().to_vec(), key.clone(), nonce.clone(), counter);
			let ciphertext = jacopone.encrypt(data);
            let data = CipherData::new(ciphertext, key, nonce, counter);
            
			let plaintext = jacopone.encrypt(data);

			//println!("{} {}", (&message[i]).as_bytes().len(), plaintext.len());

        	assert_eq!(&message[i].as_bytes().to_vec(), &plaintext);
    	}
    }
}
