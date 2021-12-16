public class Histograma{
    
    public static void main(String[] args) {
        int myArray[] = {1,2,1,3,3,1,2,1,5,1}; 
        int n = myArray.length;
        
        boolean visited[] = new boolean[n]; 

        // Recorro de 1 a 5 para ver cuántas veces se repite cada valor
        for (int i = 1; i <= 5; i++) { 
            // Cantidad de veces que se repite i
            int count = 0;// se inicia en 0 porque hasta ahora no hay coincidencias

            // Recorro el arreglo
            for (int j = 0; j < n; j++) {
                // Skip this element if already processed 
                // Esto lo hago aquí adentro porque es donde recorro el arreglo ahora
                if (visited[j] == true)
                    continue;

                // Si el valor en esa posición es el analizado (i) incremento
                if (myArray[j] == i) {
                    visited[j] = true; 
                    count++;
                } 
            } 

            // La i tiene el valor y count las veces que se repite
            System.out.print(i + ": " );
            for (int k = 0; k < count; k++) { 
                System.out.print('*');
            }
            System.out.println();
        }
    }
}
