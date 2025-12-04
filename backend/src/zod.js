import zod from "zod"

const passwordSchema = zod.object({
    username: zod.string().min(4,{message:"The username should have a minimum of 4 characters."}),
    password: zod.string().min(6,{message:"The password should have a minimum of 6 characters."}),
})

const educationSchema = zod.array(zod.object({
    college: zod.string(),
    degree: zod.string(),
    cg : zod.string(),
    start_year : zod.string(),
    end_year: zod.string()
}))

const experienceSchema = zod.array(zod.object({
    company: zod.string(),
    role: zod.string(),
    duration: zod.string(),
    description: zod.string(),
    start_date: zod.string(),
    end_date: zod.string()
}))

const skillsSchema = zod.array( zod.string().min(1).max(40) );    

const projectSchema = zod.array(zod.object({
    title: zod.string().min(1),
    github: zod.string(),
    techstack: zod.string(),
    description: zod.string()
}))

const schema = zod.object({
    username : zod.string().min(6,{message: "The username is supposed to be of 6 characters."}).max(6,{message: "The username is supposed to be of 6 characters."}), /// username should be of atleast 6 digits
    name : zod.string().min(3),
    email: zod.string(),
    phoneNumber: zod.string().min(10),
    education: educationSchema.min(1),
    skills: skillsSchema.min(1),
    experience: experienceSchema.optional(),
    projects: projectSchema.optional(),
    linkedin: zod.string().optional()
})

export {
    schema,
    projectSchema,
    educationSchema,
    experienceSchema,
    skillsSchema,
    passwordSchema
}

