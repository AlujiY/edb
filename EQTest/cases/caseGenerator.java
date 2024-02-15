package EQTest.cases;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class caseGenerator {
    
    public static void gen() {
        List<Integer> qs = Arrays.asList(233, 239, 241, 251, 257, 263, 269, 271); 
        int batch = 12;
        BigDecimal upper = new BigDecimal(2);
        upper = upper.pow(64);
        List<BigDecimal> rawList = new ArrayList<>();
        List<List<BigDecimal>> rnsList = new ArrayList<>();
        for (int i = 0; i < qs.size(); i++) {
            rnsList.add(new ArrayList<>());
        }
        for (int i = 0; i < batch; i++) {
            BigDecimal raw = upper.multiply(new BigDecimal(Math.random())).setScale(0, RoundingMode.HALF_DOWN);
            rawList.add(raw);
            for (int j = 0; j < qs.size(); j++) {
                Integer q = qs.get(j);
                BigDecimal tmp = raw.remainder(new BigDecimal(q));
                rnsList.get(j).add(tmp);
            }
        }
        for (BigDecimal b: rawList) {
            System.out.print(b + ",");
        }
        System.out.println();
        for (List<BigDecimal> list : rnsList) {
            for (BigDecimal b: list) {
                System.out.print(b + ",");
            }
            System.out.println();
        }
    }
    
    public static void main(String[] args) {
        gen();
    }
}
