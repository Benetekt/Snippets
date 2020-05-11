import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;

/**
 * @author Benetekt
 */

public class Main {
	
	public static void main(String[] args) {
		
		long time = System.currentTimeMillis();
		System.out.println("Time: " + time);
		
		
		String s = "";
		
		for(int i = 0; i < args.length; i++) {
			s += args[i];
		}
		
		Encrypter en = new Encrypter(generateSeed(time)*7919);
		
		System.out.println(Base64.getEncoder().encodeToString(BCode.translate(en.encode(s)).getBytes()));
	}
	
	public static long generateSeed(long seed) {
        String seed64 = "3132333435363738393031323334353637383930" +
        "3132333435363738393031323334353637383930" +
        "3132333435363738393031323334353637383930" +
        "31323334";
		
		long se = seed/30;
		
		se = Integer.parseInt( TOTP.generateTOTP(seed64, Long.toString(se), "8", "HmacSHA512"));
		
		return se;
	}
	
	
}
class BCode{
	
	private static HashMap<Character, String> btable = new HashMap<Character, String>();
	
	static {
		btable.put(' ', "   ");
		btable.put('A', "hhtt");
		btable.put('B', "hthh");
		btable.put('C', "htth");
		btable.put('D', "thh");
		btable.put('E', "ttth");
		btable.put('F', "tth");
		btable.put('G', "h");
		btable.put('H', "ttt");
		btable.put('I', "tht");
		btable.put('J', "hhth");
		btable.put('K', "thht");
		btable.put('L', "hhh");
		btable.put('M', "ht");
		btable.put('N', "hh");
		btable.put('O', "thtt");
		btable.put('P', "hth");
		btable.put('Q', "thhh");
		btable.put('R', "tt");
		btable.put('S', "tttt");
		btable.put('T', "hht");
		btable.put('U', "ttht");
		btable.put('V', "t");
		btable.put('W', "htt");
		btable.put('X', "htht");
		btable.put('Y', "httt");
		btable.put('Z', "th");
		btable.put('1', "hhhhh");
		btable.put('2', "hhhht");
		btable.put('3', "hhhtt");
		btable.put('4', "hhttt");
		btable.put('5', "htttt");
		btable.put('6', "ttttt");
		btable.put('7', "tttth");
		btable.put('8', "ttthh");
		btable.put('9', "tthhh");
		btable.put('0', "thhhh");
	}
	
	public static String translate(String text) {
		String res = "";
		
		char[] cl = text.toUpperCase().toCharArray();
		
		for(char c : cl) {
			if(btable.containsKey(c)) {
				res += btable.get(c) + " ";
			} else {
				res += c + " ";
			}
		}
		
		return res;
	}
}

class Encrypter {
	static long seed;
	
	private HashMap<Character, Character> etable = new HashMap<Character, Character>();
	
	public Encrypter(long seed) {
		this.seed = seed;
		fillTable();
	}
	
	public void setSeed(long seed){
		this.seed = seed;
		
		fillTable();
	}
	
	public long getSeed() {
		return seed;
	}
	
	private void update() {
		seed = (long) (seed*10*14.636848*5234809);
	}
	
	private void fillTable() {
		ArrayList<Integer> occupied = new ArrayList<Integer>();
		etable.clear();
		
		int i = 0;
		int e = 26;
		
		while(i < 25) {
			int c = generateInt(e);
			
			if(occupied.contains(c)) {
				
				
				while(occupied.contains(c)) {
					if(c > 26) {
						c -= 25;
					}
					
					c++;
				}
				
				if(c > 0 && c + 65 < 91) {
					if(!occupied.contains(c)) {
						
						occupied.add(c);
						etable.put((char)(i + 65), (char)( c + 64 ));
						
						i++;
					}
				}
				e += 26;
			} else {
				occupied.add(c);
				etable.put((char)(i + 65), (char)( c + 65 ));
				
				i++;
				e += 26;
			}
		}
		
		if(occupied.size() == 25) {
			for (int j = 0; j < 26; j++) {
				if(!occupied.contains(j)) {
					occupied.add(j);
					etable.put((char)(i + 65), (char)( j + 65 ));
				}
			}
		}
	}
	
	public String encode(String test) {
		String res = "";
		
		String[] words = test.toUpperCase().split(" ");
		
		for(String w : words) {
			String word = "";
			
			char[] chars = w.toCharArray();
			
			for(char c : chars) {
				if(etable.containsKey(c)) {
					char ec = etable.get(c);
					word = word + ec;
				} else {
					word = word + c;
				}
			}
			
			res += word + " ";
		}
		
		return res;
	}
	
	public int generateInt(int i) {
		
		update();
		
		int num = Math.floorMod((int) Math.pow(7919, seed), (i+7919));
		
		num = (int) Math.pow(num, 7727);
		
		num = (int) (num * 1.5);
		
		while(num > 25) {
			num = num - 25;
		}
	
		return num;
	}
}

/**
 * @author Johan Rydell, PortWise, Inc.
 */

class TOTP {

    private TOTP() {}
    
    private static byte[] hmac_sha(String crypto, byte[] keyBytes,
            byte[] text){
        try {
            Mac hmac;
            hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey =
                new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }

    private static byte[] hexStr2Bytes(String hex){
        byte[] bArray = new BigInteger("10" + hex,16).toByteArray();

        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i+1];
        return ret;
    }

    private static final int[] DIGITS_POWER
    // 0 1  2   3    4     5      6       7        8
    = {1,10,100,1000,10000,100000,1000000,10000000,100000000 };

    public static String generateTOTP(String key,
            String time,
            String returnDigits){
        return generateTOTP(key, time, returnDigits, "HmacSHA1");
    }

    public static String generateTOTP256(String key,
            String time,
            String returnDigits){
        return generateTOTP(key, time, returnDigits, "HmacSHA256");
    }

    public static String generateTOTP512(String key,
            String time,
            String returnDigits){
        return generateTOTP(key, time, returnDigits, "HmacSHA512");
    }

    public static String generateTOTP(String key,
            String time,
            String returnDigits,
            String crypto){
        int codeDigits = Integer.decode(returnDigits).intValue();
        String result = null;
 
        while (time.length() < 16 )
            time = "0" + time;

        byte[] msg = hexStr2Bytes(time);
        byte[] k = hexStr2Bytes(key);

        byte[] hash = hmac_sha(crypto, k, msg);

        int offset = hash[hash.length - 1] & 0xf;

        int binary =
            ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        result = Integer.toString(otp);
        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }
}
