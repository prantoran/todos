Step 1) 

Understand the code from  
and  (the lawyer must have edited the audit report)
and make them into a singular lambda function. 

Eval metrics:
OCR accuracy ( transactions retrieval ) 
Correction accuracy ( difference between original generations and corrected ones by the lawyer / firm ) 
Token counting + costs in total
Audit agent context window error rate
Retrieval accuracy 
Determined by comparing retrieved examples from the RAG to whether it was corrected by a human.
Semantic/ Context Precision 
	•		•	If any retrieved example is in the same domain as your final label (human), you count that as “1.” Otherwise “0.” Then take the average. That tells you how often the retriever at least got the context correct.

Step 2) 
Come up with a plan for frontend (basic design) and backend. Whats the most efficient way for us to visualize how well our agentic pipeline is performing and how we can quickly search up things by job id or user. Prioritize an MVP style and dont get lost with making it too complex. 


Step 3) 
combine all code into lambda function


